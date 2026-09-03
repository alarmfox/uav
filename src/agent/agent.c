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
#include "utils.h"

#define UAV_AGENT_DIR "/run/uav"
#define UAV_AGENT_PROGRAM_TEMPLATE UAV_AGENT_DIR "/uav_program_XXXXXX"

struct uav_agent_state {
  int control_fd;
  int daemon_fd;
  pid_t program_pid;
  uint64_t program_deadline_ms;
  int program_timed_out;
  int pending_upload_fd;
  uint32_t pending_upload_remaining;
  mode_t pending_upload_mode;
  enum uav_agent_upload_purpose pending_upload_purpose;
  char pending_upload_path[PATH_MAX];
  enum uav_agent_upload_purpose upload_purpose;
  char upload_path[PATH_MAX];
};

static struct uav_agent_state agent = {
    .control_fd = -1,
    .daemon_fd = -1,
    .program_pid = -1,
    .program_deadline_ms = 0,
    .program_timed_out = 0,
    .pending_upload_fd = -1,
    .pending_upload_remaining = 0,
    .pending_upload_mode = 0,
    .pending_upload_purpose = 0,
    .pending_upload_path = {0},
    .upload_purpose = 0,
    .upload_path = {0},
};

static void print_help(void);
static int uav_agent_parse_options(int argc, char* const argv[]);
static int uav_agent_setup(void);
static void uav_agent_cleanup(void);
static int uav_agent_loop(void);
static int uav_agent_dispatch(const struct uav_proto_msg* msg);
static int uav_agent_upload_begin(const struct uav_proto_msg* msg);
static int uav_agent_upload_chunk(const struct uav_proto_msg* msg);
static int uav_agent_upload_end(const struct uav_proto_msg* msg);
static void uav_agent_discard_pending_upload(void);
static int uav_agent_run(const struct uav_proto_msg* msg);
static int uav_agent_register_workload(void);
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

  if (uav_configure_fd(agent.control_fd) < 0) return -1;
  if (uav_configure_fd(agent.daemon_fd) < 0) return -1;

  if (mkdir(UAV_AGENT_DIR, 0711) < 0 && errno != EEXIST) return -1;

  if (prctl(PR_SET_DUMPABLE, 0) < 0) return -1;

  /* Complete the START request issued by the sandbox entrypoint. */
  return uav_agent_proto_send_response(agent.control_fd, UAV_AGENT_MSG_START, 0,
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

  uav_agent_discard_pending_upload();

  if (agent.control_fd >= 0) close(agent.control_fd);
  agent.control_fd = -1;

  if (agent.daemon_fd >= 0) close(agent.daemon_fd);
  agent.daemon_fd = -1;

  if (agent.upload_path[0] != '\0') {
    unlink(agent.upload_path);
    agent.upload_path[0] = '\0';
  }
}

static void uav_agent_discard_pending_upload(void) {
  if (agent.pending_upload_fd >= 0) close(agent.pending_upload_fd);
  agent.pending_upload_fd = -1;

  if (agent.pending_upload_path[0] != '\0') unlink(agent.pending_upload_path);
  agent.pending_upload_path[0] = '\0';
  agent.pending_upload_remaining = 0;
  agent.pending_upload_mode = 0;
  agent.pending_upload_purpose = 0;
}

static int uav_agent_upload_begin(const struct uav_proto_msg* msg) {
  char path[] = UAV_AGENT_PROGRAM_TEMPLATE;
  int flags;
  mode_t effective_mode;
  struct uav_agent_upload_meta meta;

  if (agent.program_pid > 0 || agent.pending_upload_fd >= 0) {
    errno = EBUSY;
    return -1;
  }

  if (uav_agent_proto_decode_upload_begin(msg, &meta) < 0) return -1;

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
  agent.pending_upload_fd = mkstemp(path);
  if (agent.pending_upload_fd < 0) return -1;
  strcpy(agent.pending_upload_path, path);

  flags = fcntl(agent.pending_upload_fd, F_GETFD);
  if (flags < 0 ||
      fcntl(agent.pending_upload_fd, F_SETFD, flags | FD_CLOEXEC) < 0) {
    int saved_errno = errno;

    uav_agent_discard_pending_upload();
    errno = saved_errno;
    return -1;
  }

  agent.pending_upload_remaining = meta.size;
  agent.pending_upload_mode = effective_mode;
  agent.pending_upload_purpose = meta.purpose;
  return uav_agent_proto_send_response(agent.control_fd,
                                       UAV_AGENT_MSG_UPLOAD_BEGIN, 0, NULL, 0);
}

static int uav_agent_upload_chunk(const struct uav_proto_msg* msg) {
  if (agent.pending_upload_fd < 0 || msg->length == 0 ||
      msg->length > UAV_AGENT_PROTO_MAX_CHUNK ||
      msg->length > agent.pending_upload_remaining) {
    errno = EPROTO;
    return -1;
  }

  if (uav_write_all(agent.pending_upload_fd, msg->payload, msg->length) < 0)
    return -1;

  agent.pending_upload_remaining -= msg->length;
  return uav_agent_proto_send_response(agent.control_fd,
                                       UAV_AGENT_MSG_UPLOAD_CHUNK, 0, NULL, 0);
}

static int uav_agent_upload_end(const struct uav_proto_msg* msg) {
  int fd;

  if (agent.pending_upload_fd < 0 || msg->length != 0 ||
      agent.pending_upload_remaining != 0) {
    errno = EPROTO;
    return -1;
  }

  if (fchmod(agent.pending_upload_fd, agent.pending_upload_mode) < 0) return -1;

  fd = agent.pending_upload_fd;
  agent.pending_upload_fd = -1;
  if (close(fd) < 0) {
    int saved_errno = errno;

    uav_agent_discard_pending_upload();
    errno = saved_errno;
    return -1;
  }

  if (agent.upload_path[0] != '\0') unlink(agent.upload_path);
  strcpy(agent.upload_path, agent.pending_upload_path);
  agent.upload_purpose = agent.pending_upload_purpose;
  agent.pending_upload_path[0] = '\0';
  agent.pending_upload_remaining = 0;
  agent.pending_upload_mode = 0;
  agent.pending_upload_purpose = 0;

  return uav_agent_proto_send_response(agent.control_fd,
                                       UAV_AGENT_MSG_UPLOAD_END, 0, NULL, 0);
}

static int uav_agent_register_workload(void) {
  struct uav_proto_msg response;

  if (uav_daemon_proto_send_request(
          agent.daemon_fd, UAV_DAEMON_MSG_REGISTER_WORKLOAD, NULL, 0) < 0)
    return -1;
  if (uav_daemon_proto_receive_response(
          agent.daemon_fd, UAV_DAEMON_MSG_REGISTER_WORKLOAD, &response) < 0)
    return -1;
  if (response.length != 0) {
    errno = EPROTO;
    return -1;
  }
  if (response.error != 0) {
    errno = response.error;
    return -1;
  }
  return 0;
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

  if (msg->length == 0) {
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
    if (uav_agent_drop_capabilities() != 0) _exit(126);

    /* The daemon receives this SEQPACKET request and its credentials together.
     */
    if (uav_agent_register_workload() < 0) _exit(125);

    /*
     * Closes only the child's descriptor. The agent's descriptor remains
     * open because fork() created a separate descriptor table.
     */
    if (agent.control_fd >= 0) close(agent.control_fd);
    agent.control_fd = -1;

    if (agent.daemon_fd >= 0) close(agent.daemon_fd);
    agent.daemon_fd = -1;

    execve(agent.upload_path, request.argv, request.envp);
    _exit(127);
  }

  uav_agent_proto_free_run(&request);
  agent.program_pid = pid;
  agent.program_deadline_ms = duration_ms == 0 ? 0 : now_ms + duration_ms;
  agent.program_timed_out = 0;
  return 0;
}

static int uav_agent_check_program(void) {
  uint8_t payload[sizeof(uint32_t)];
  int response_error;
  pid_t pid;
  int status;

  if (agent.program_pid <= 0) return 0;

  do {
    pid = waitpid(agent.program_pid, &status, WNOHANG);
  } while (pid < 0 && errno == EINTR);

  if (pid == 0) return 0;
  if (pid < 0) {
    int saved_errno = errno;

    uav_agent_proto_send_response(agent.control_fd, UAV_AGENT_MSG_RUN,
                                  saved_errno, NULL, 0);
    errno = saved_errno;
    return -1;
  }

  agent.program_pid = -1;
  agent.program_deadline_ms = 0;
  response_error = agent.program_timed_out ? ETIMEDOUT : 0;
  agent.program_timed_out = 0;
  uav_proto_put_u32(payload, (uint32_t)status);
  return uav_agent_proto_send_response(agent.control_fd, UAV_AGENT_MSG_RUN,
                                       response_error, payload,
                                       sizeof(payload));
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
  if (agent.program_pid > 0 || (agent.pending_upload_fd >= 0 &&
                                msg->type != UAV_AGENT_MSG_UPLOAD_CHUNK &&
                                msg->type != UAV_AGENT_MSG_UPLOAD_END)) {
    errno = EBUSY;
    return -1;
  }

  switch (msg->type) {
    case UAV_AGENT_MSG_UPLOAD_BEGIN:
      return uav_agent_upload_begin(msg);

    case UAV_AGENT_MSG_UPLOAD_CHUNK:
      return uav_agent_upload_chunk(msg);

    case UAV_AGENT_MSG_UPLOAD_END:
      return uav_agent_upload_end(msg);

    case UAV_AGENT_MSG_RUN:
      return uav_agent_run(msg);

    case UAV_AGENT_MSG_SHUTDOWN:
      if (msg->length != 0) {
        errno = EPROTO;
        return -1;
      }
      if (uav_agent_proto_send_response(agent.control_fd,
                                        UAV_AGENT_MSG_SHUTDOWN, 0, NULL, 0) < 0)
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
      if (uav_agent_proto_receive_request(agent.control_fd, &msg) < 0)
        return -1;

      ret = uav_agent_dispatch(&msg);
      if (ret < 0) {
        int saved_errno = errno;

        uav_agent_proto_send_response(agent.control_fd, msg.type, saved_errno,
                                      NULL, 0);
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
