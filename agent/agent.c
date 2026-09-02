#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <grp.h>
#include <limits.h>
#include <linux/securebits.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/capability.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "agent_protocol.h"
#include "daemon_protocol.h"
#include "transport.h"

#define UAV_AGENT_DIR "/run/uav"
#define UAV_AGENT_PROGRAM_TEMPLATE UAV_AGENT_DIR "/uav_program_XXXXXX"

struct uav_agent_state {
  int control_fd;
  int daemon_fd;
  struct uav_transport* control_transport;
  struct uav_transport* daemon_transport;
  pid_t program_pid;
  uint64_t program_deadline_ms;
  int program_timed_out;
  enum uav_agent_upload_purpose upload_purpose;
  char upload_path[PATH_MAX];
};

static struct uav_agent_state agent = {
    .control_fd = -1,
    .daemon_fd = -1,
    .control_transport = NULL,
    .program_pid = -1,
    .program_deadline_ms = 0,
    .program_timed_out = 0,
    .upload_purpose = 0,
    .upload_path = {0},
};

static void print_help(void);
static int uav_agent_parse_options(int argc, char* const argv[]);
static int uav_agent_setup(void);
static void uav_agent_cleanup(void);
static int uav_agent_loop(void);
static int uav_agent_dispatch(const struct uav_proto_msg* msg);
static int uav_agent_upload(const struct uav_proto_msg* begin);
static int uav_agent_run(const struct uav_proto_msg* msg);
static int uav_agent_kill(void);
static int uav_agent_check_program(void);
static int uav_agent_get_monotonic_ms(uint64_t* milliseconds);
static int uav_agent_get_poll_timeout(int* timeout);
static int uav_agent_timeout_program(void);
static int uav_agent_drop_capabilities(void);

static void print_help(void) {
  printf("Usage: uav-agent --control-fd <fd> --daemon-fd <fd>\n\n");
  printf("Options:\n");
  printf("  -f, --control-fd <fd>   Host file descriptor number\n");
  printf("  -d, --daemon-fd <fd>   Daemon file descriptor number\n");
  printf("  -h, --help              Show this help message\n");
}

static int uav_agent_parse_options(int argc, char* const argv[]) {
  static const struct option long_options[] = {
      {"control-fd", required_argument, NULL, 'f'},
      {"daemon-fd", required_argument, NULL, 'd'},
      {"help", no_argument, NULL, 'h'},
      {NULL, 0, NULL, 0}};
  char* end;
  long value;
  int opt;

  while ((opt = getopt_long(argc, argv, "f:d:h", long_options, NULL)) != -1) {
    switch (opt) {
      case 'f':
        errno = 0;
        end = NULL;
        value = strtol(optarg, &end, 10);
        if (errno != 0 || end == optarg || *end != '\0' || value < 0 ||
            value > INT32_MAX) {
          errno = EINVAL;
          return -1;
        }
        agent.control_fd = (int)value;
        break;

      case 'd':
        errno = 0;
        end = NULL;
        value = strtol(optarg, &end, 10);
        if (errno != 0 || end == optarg || *end != '\0' || value < 0 ||
            value > INT32_MAX) {
          errno = EINVAL;
          return -1;
        }
        agent.daemon_fd = (int)value;
        break;

      case 'h':
        print_help();
        return 1;

      default:
        errno = EINVAL;
        return -1;
    }
  }

  if (agent.control_fd < 0 || agent.daemon_fd < 0 || optind != argc) {
    errno = EINVAL;
    return -1;
  }

  return 0;
}

static int uav_configure_fd(int fd) {
  int flags;

  flags = fcntl(fd, F_GETFD);
  if (flags < 0) return -1;

  return fcntl(fd, F_SETFD, flags | FD_CLOEXEC);
}

static int uav_agent_setup(void) {
  if (signal(SIGPIPE, SIG_IGN) == SIG_ERR) return -1;

  if(uav_configure_fd(agent.control_fd) < 0) return -1;
  if(uav_configure_fd(agent.daemon_fd) < 0) return -1;

  if (mkdir(UAV_AGENT_DIR, 0711) < 0 && errno != EEXIST) return -1;

  if (prctl(PR_SET_DUMPABLE, 0) < 0) return -1;

  agent.control_transport = uav_fd_transport_create(agent.control_fd);
  if (agent.control_transport == NULL) return -1;

  agent.daemon_transport = uav_fd_transport_create(agent.daemon_fd);
  if (agent.daemon_transport == NULL) return -1;

  /* Complete the START request issued by the sandbox entrypoint. */
  return uav_agent_proto_send_response(agent.control_transport, UAV_AGENT_MSG_START, 0,
                                       NULL, 0);
}

static void uav_agent_cleanup(void) {
  if (agent.program_pid > 0) {
    int status;

    kill(agent.program_pid, SIGKILL);
    while (waitpid(agent.program_pid, &status, 0) < 0 && errno == EINTR) {
    }
    agent.program_pid = -1;
    agent.program_deadline_ms = 0;
    agent.program_timed_out = 0;
  }

  uav_transport_destroy(&agent.control_transport);
  agent.control_fd = -1;

  uav_transport_destroy(&agent.daemon_transport);
  agent.daemon_fd = -1;

  if (agent.upload_path[0] != '\0') {
    unlink(agent.upload_path);
    agent.upload_path[0] = '\0';
  }
}

static int uav_agent_upload(const struct uav_proto_msg* begin) {
  char path[] = UAV_AGENT_PROGRAM_TEMPLATE;
  int fd = -1;
  int flags;
  int saved_errno;
  int ret = -1;
  mode_t effective_mode;
  struct uav_agent_upload_meta meta;

  if (agent.program_pid > 0) {
    errno = EBUSY;
    return -1;
  }

  if (uav_agent_proto_decode_upload_begin(begin, &meta) < 0) return -1;

  switch (meta.purpose) {
    case UAV_AGENT_UPLOAD_EXECUTABLE:
      effective_mode = 0555;
      break;
    case UAV_AGENT_UPLOAD_DATA:
      effective_mode = 0444;
      break;
    default:
      errno = EPROTO;
      return -1;
  }

  /* mkstemp gives every uploaded file a private, unpredictable pathname. */
  fd = mkstemp(path);
  if (fd < 0) goto out;

  flags = fcntl(fd, F_GETFD);
  if (flags < 0 || fcntl(fd, F_SETFD, flags | FD_CLOEXEC) < 0) goto out;

  if (uav_agent_proto_send_response(agent.control_transport, UAV_AGENT_MSG_UPLOAD_BEGIN,
                                    0, NULL, 0) < 0)
    goto out;
  if (uav_agent_proto_receive_upload(agent.control_transport, fd, meta.size) < 0)
    goto out;

  if (fchmod(fd, effective_mode) < 0) goto out;

  if (close(fd) < 0) {
    fd = -1;
    goto out;
  }
  fd = -1;

  ret = uav_agent_proto_send_response(agent.control_transport, UAV_AGENT_MSG_UPLOAD_END,
                                      0, NULL, 0);
  if (ret < 0) goto out;

  if (agent.upload_path[0] != '\0') unlink(agent.upload_path);

  strcpy(agent.upload_path, path);
  agent.upload_purpose = meta.purpose;

out:
  saved_errno = errno;
  if (fd >= 0) close(fd);
  if (ret < 0) unlink(path);
  errno = saved_errno;
  return ret;
}

static int uav_agent_run(const struct uav_proto_msg* msg) {
  struct uav_agent_exec_request request;
  uint64_t now_ms;
  uint64_t duration_ms;
  pid_t pid;

  if (agent.upload_path[0] == '\0' ||
      agent.upload_purpose != UAV_AGENT_UPLOAD_EXECUTABLE) {
    errno = ENOENT;
    return -1;
  }

  if (agent.program_pid > 0) {
    errno = EBUSY;
    return -1;
  }

  if (msg->header.length == 0) {
    errno = EPROTO;
    return -1;
  }

  if (uav_agent_proto_decode_run(msg, &request) < 0) return -1;

  now_ms = 0;
  duration_ms = 0;
  if (request.duration_seconds != 0) {
    duration_ms = (uint64_t)request.duration_seconds * 1000;
    if (uav_agent_get_monotonic_ms(&now_ms) < 0) {
      int saved_errno = errno;

      uav_agent_proto_free_run(&request);
      errno = saved_errno;
      return -1;
    }
    if (now_ms > UINT64_MAX - duration_ms) {
      uav_agent_proto_free_run(&request);
      errno = EOVERFLOW;
      return -1;
    }
  }

  pid = fork();
  if (pid < 0) {
    uav_agent_proto_free_run(&request);
    return -1;
  }

  if (pid == 0) {
    /*
     * Do setup while still in the agent cgroup, so these operations are not
     * attributed to the untrusted workload.
     */
    if (uav_agent_drop_capabilities() != 0)
      _exit(126);

    /*
     * send() is sufficient. SO_PASSCRED causes the kernel to attach this
     * process's SCM_CREDENTIALS.
     */
    if (uav_daemon_proto_register_workload(agent.daemon_transport) < 0)
      _exit(125);

    /*
     * Closes only the child's descriptor. The agent's descriptor remains
     * open because fork() created a separate descriptor table.
     */
    uav_transport_destroy(&agent.daemon_transport);
    agent.daemon_fd = -1;

    uav_transport_destroy(&agent.control_transport);
    agent.control_fd = -1;


    execve(agent.upload_path, request.argv, request.envp);
    _exit(127);
  }

  uav_agent_proto_free_run(&request);
  agent.program_pid = pid;
  agent.program_deadline_ms = duration_ms == 0 ? 0 : now_ms + duration_ms;
  agent.program_timed_out = 0;
  return uav_agent_proto_send_response(agent.control_transport, UAV_AGENT_MSG_RUN, 0,
                                       NULL, 0);
}

static int uav_agent_kill(void) {
  if (agent.program_pid <= 0) {
    errno = ESRCH;
    return -1;
  }

  if (kill(agent.program_pid, SIGKILL) < 0 && errno != ESRCH) return -1;

  return uav_agent_proto_send_response(agent.control_transport, UAV_AGENT_MSG_KILL, 0,
                                       NULL, 0);
}

static int uav_agent_check_program(void) {
  pid_t pid;
  int status;

  if (agent.program_pid <= 0) return 0;

  do {
    pid = waitpid(agent.program_pid, &status, WNOHANG);
  } while (pid < 0 && errno == EINTR);

  if (pid == 0) return 0;
  if (pid < 0) return -1;

  agent.program_pid = -1;
  agent.program_deadline_ms = 0;

  if (agent.program_timed_out) {
    uint8_t payload[sizeof(uint32_t)];

    agent.program_timed_out = 0;
    uav_proto_put_u32(payload, ETIMEDOUT);
    if (uav_agent_proto_send_event(agent.control_transport, UAV_AGENT_MSG_EVENT,
                                   payload, sizeof(payload)) < 0)
      return -1;
  }

  return uav_agent_proto_send_program_exit(agent.control_transport, status);
}

static int uav_agent_get_monotonic_ms(uint64_t* milliseconds) {
  struct timespec now;
  uintmax_t seconds;
  uintmax_t seconds_ms;
  uintmax_t partial;

  if (milliseconds == NULL) {
    errno = EINVAL;
    return -1;
  }

  if (clock_gettime(CLOCK_MONOTONIC, &now) < 0) return -1;
  if (now.tv_sec < 0 || now.tv_nsec < 0 || now.tv_nsec >= 1000000000L) {
    errno = EPROTO;
    return -1;
  }

  seconds = (uintmax_t)now.tv_sec;
  if (seconds > UINT64_MAX / 1000) {
    errno = EOVERFLOW;
    return -1;
  }

  seconds_ms = seconds * 1000;
  partial = (uintmax_t)now.tv_nsec / 1000000;
  if (partial > UINT64_MAX - seconds_ms) {
    errno = EOVERFLOW;
    return -1;
  }

  *milliseconds = (uint64_t)(seconds_ms + partial);
  return 0;
}

static int uav_agent_get_poll_timeout(int* timeout) {
  uint64_t now_ms;
  uint64_t remaining_ms;

  if (timeout == NULL) {
    errno = EINVAL;
    return -1;
  }

  if (agent.program_pid <= 0) {
    *timeout = -1;
    return 0;
  }

  /* Keep polling so an untimed child is still reaped promptly. */
  if (agent.program_deadline_ms == 0) {
    *timeout = 100;
    return 0;
  }

  if (uav_agent_get_monotonic_ms(&now_ms) < 0) return -1;
  if (now_ms >= agent.program_deadline_ms) {
    *timeout = 0;
    return 0;
  }

  remaining_ms = agent.program_deadline_ms - now_ms;
  *timeout = remaining_ms > 100 ? 100 : (int)remaining_ms;
  return 0;
}

static int uav_agent_timeout_program(void) {
  if (agent.program_pid <= 0) return 0;

  if (kill(agent.program_pid, SIGKILL) < 0 && errno != ESRCH) return -1;

  agent.program_timed_out = 1;
  return 0;
}

static int uav_agent_dispatch(const struct uav_proto_msg* msg) {
  if (msg->header.kind != UAV_PROTO_REQUEST) {
    errno = EPROTO;
    return -1;
  }

  switch (msg->header.type) {
    case UAV_AGENT_MSG_UPLOAD_BEGIN:
      return uav_agent_upload(msg);

    case UAV_AGENT_MSG_RUN:
      return uav_agent_run(msg);

    case UAV_AGENT_MSG_KILL:
      if (msg->header.length != 0) {
        errno = EPROTO;
        return -1;
      }
      return uav_agent_kill();

    case UAV_AGENT_MSG_SHUTDOWN:
      if (msg->header.length != 0) {
        errno = EPROTO;
        return -1;
      }
      if (uav_agent_proto_send_response(agent.control_transport, UAV_AGENT_MSG_SHUTDOWN,
                                        0, NULL, 0) < 0)
        return -1;
      return 1;

    default:
      errno = EPROTO;
      return -1;
  }
}

static int uav_agent_loop(void) {
  struct pollfd fd = {.fd = agent.control_fd, .events = POLLIN};
  struct uav_proto_msg msg;
  int timeout;
  int ret;

  for (;;) {
    if (uav_agent_check_program() < 0) return -1;

    if (uav_agent_get_poll_timeout(&timeout) < 0) return -1;
    if (timeout == 0) {
      if (uav_agent_timeout_program() < 0) return -1;
      continue;
    }

    do {
      ret = poll(&fd, 1, timeout);
    } while (ret < 0 && errno == EINTR);

    if (ret < 0) return -1;
    if (ret == 0) continue;

    if (fd.revents & POLLIN) {
      if (uav_agent_proto_recv(agent.control_transport, &msg) < 0) return -1;

      ret = uav_agent_dispatch(&msg);
      if (ret < 0) {
        int saved_errno = errno;

        if (msg.header.kind == UAV_PROTO_REQUEST)
          uav_agent_proto_send_response(agent.control_transport, msg.header.type,
                                        saved_errno, NULL, 0);
        errno = saved_errno;
        return -1;
      }
      if (ret > 0) return 0;
    }

    if (fd.revents & (POLLERR | POLLHUP | POLLNVAL)) {
      errno = ECONNRESET;
      return -1;
    }
  }
}

static int uav_agent_drop_capabilities(void) {
  cap_t empty;
  int cap;
  int ret;
  int saved_errno;

  if (cap_set_secbits(SECBIT_NOROOT | SECBIT_NOROOT_LOCKED |
                      SECBIT_NO_SETUID_FIXUP | SECBIT_NO_SETUID_FIXUP_LOCKED) <
      0)
    return -1;

  if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0) return -1;

  if (cap_reset_ambient() < 0) return -1;

  /* CAP_SETPCAP is still effective here. */
  for (cap = 0; cap < cap_max_bits(); cap++) {
    ret = cap_get_bound(cap);
    if (ret < 0) return -1;

    if (ret && cap_drop_bound(cap) < 0) return -1;
  }

  /* Do this last: clear effective, permitted and inheritable sets. */
  empty = cap_init();
  if (empty == NULL) return -1;

  ret = cap_set_proc(empty);
  saved_errno = errno;
  cap_free(empty);

  if (ret < 0) {
    errno = saved_errno;
    return -1;
  }

  return 0;
}

int main(int argc, char* argv[]) {
  int ret;

  ret = uav_agent_parse_options(argc, argv);
  if (ret > 0) return EXIT_SUCCESS;
  if (ret < 0) {
    print_help();
    return EXIT_FAILURE;
  }

  printf("[UAV-AGENT] starting\n");

  if (uav_agent_setup() < 0) {
    int saved_errno = errno;
    fprintf(stderr, "[UAV-AGENT] setup failed: %s\n", strerror(saved_errno));
    uav_agent_cleanup();
    return EXIT_FAILURE;
  }
  printf("[UAV-AGENT] starting complete\n");

  if (uav_agent_loop() < 0) {
    int saved_errno = errno;
    fprintf(stderr, "[UAV-AGENT] protocol loop failed: %s\n",
            strerror(saved_errno));
    uav_agent_cleanup();
    return EXIT_FAILURE;
  }

  uav_agent_cleanup();
  return EXIT_SUCCESS;
}
