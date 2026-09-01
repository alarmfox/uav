#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <grp.h>
#include <limits.h>
#include <linux/prctl.h>
#include <linux/securebits.h>
#include <poll.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/capability.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <termios.h>
#include <unistd.h>

#include "agent_protocol.h"
#include "transport.h"

#define UAV_AGENT_DIR "/run/uav"
#define UAV_AGENT_PROGRAM_TEMPLATE UAV_AGENT_DIR "/uav_program_XXXXXX"

struct uav_agent_state {
  int control_fd;
  struct uav_transport* transport;
  pid_t program_pid;
  bool upload_ready;
  enum uav_agent_upload_purpose upload_purpose;
  char upload_path[PATH_MAX];
};

static struct uav_agent_state agent = {
    .control_fd = -1,
    .transport = NULL,
    .program_pid = -1,
    .upload_ready = false,
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
static int uav_agent_send_error(int error);
static int uav_agent_drop_capabilities(void);

static void print_help(void) {
  printf("Usage: uav-agent --control-fd <fd>\n\n");
  printf("Options:\n");
  printf("  -f, --control-fd <fd>   File descriptor number\n");
  printf("  -h, --help              Show this help message\n");
}

static int uav_agent_parse_options(int argc, char* const argv[]) {
  static const struct option long_options[] = {
      {"control-fd", required_argument, NULL, 'f'},
      {"help", no_argument, NULL, 'h'},
      {NULL, 0, NULL, 0}};
  char* end;
  long value;
  int opt;

  while ((opt = getopt_long(argc, argv, "f:h", long_options, NULL)) != -1) {
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

      case 'h':
        print_help();
        return 1;

      default:
        errno = EINVAL;
        return -1;
    }
  }

  if (agent.control_fd < 0 || optind != argc) {
    errno = EINVAL;
    return -1;
  }

  return 0;
}

static int uav_agent_setup(void) {
  struct termios termios;
  int flags;

  if (signal(SIGPIPE, SIG_IGN) == SIG_ERR) return -1;

  flags = fcntl(agent.control_fd, F_GETFD);
  if (flags < 0) return -1;

  if (fcntl(agent.control_fd, F_SETFD, flags | FD_CLOEXEC) < 0) return -1;

  if (isatty(agent.control_fd)) {
    if (tcgetattr(agent.control_fd, &termios) < 0) return -1;
    cfmakeraw(&termios);
    if (tcsetattr(agent.control_fd, TCSANOW, &termios) < 0) return -1;
  }

  if (mkdir(UAV_AGENT_DIR, 0711) < 0 && errno != EEXIST) return -1;

  if (prctl(PR_SET_DUMPABLE, 0) < 0) return -1;

  agent.transport = uav_fd_transport_create(agent.control_fd);
  if (agent.transport == NULL) return -1;

  /* Setup is complete. The host may start sending commands. */
  return uav_agent_proto_send(agent.transport, UAV_AGENT_MSG_READY, NULL, 0);
}

static void uav_agent_cleanup(void) {
  if (agent.program_pid > 0) {
    int status;

    kill(agent.program_pid, SIGKILL);
    while (waitpid(agent.program_pid, &status, 0) < 0 && errno == EINTR) {
    }
    agent.program_pid = -1;
  }

  uav_transport_destroy(&agent.transport);
  agent.control_fd = -1;

  if (agent.upload_ready) {
    unlink(agent.upload_path);
    agent.upload_ready = false;
    agent.upload_path[0] = '\0';
  }
}

static int uav_agent_send_error(int error) {
  if (agent.transport == NULL) return -1;
  return uav_agent_proto_send_error(agent.transport, error);
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

  if (uav_agent_proto_accept_upload(agent.transport) < 0) goto out;
  if (uav_agent_proto_receive_upload(agent.transport, fd, meta.size) < 0)
    goto out;

  if (fchmod(fd, effective_mode) < 0) goto out;

  if (close(fd) < 0) {
    fd = -1;
    goto out;
  }
  fd = -1;

  ret = uav_agent_proto_complete_upload(agent.transport);
  if (ret < 0) goto out;

  if (agent.upload_ready) unlink(agent.upload_path);

  strcpy(agent.upload_path, path);
  agent.upload_purpose = meta.purpose;
  agent.upload_ready = true;

out:
  saved_errno = errno;
  if (fd >= 0) close(fd);
  if (ret < 0) unlink(path);
  errno = saved_errno;
  return ret;
}

static int uav_agent_run(const struct uav_proto_msg* msg) {
  pid_t pid;

  if (msg->header.length != 0) {
    errno = EPROTO;
    return -1;
  }

  if (!agent.upload_ready ||
      agent.upload_purpose != UAV_AGENT_UPLOAD_EXECUTABLE) {
    errno = ENOENT;
    return -1;
  }

  if (agent.program_pid > 0) {
    errno = EBUSY;
    return -1;
  }

  pid = fork();
  if (pid < 0) return -1;

  if (pid == 0) {
    char* const argv[] = {agent.upload_path, NULL};
    char* const envp[] = {NULL};

    /* The analyzed program must not inherit the agent's control channel. */
    close(agent.control_fd);

    if (uav_agent_drop_capabilities() != 0) _exit(126);

    execve(agent.upload_path, argv, envp);
    _exit(127);
  }

  agent.program_pid = pid;
  return 0;
}

static int uav_agent_kill(void) {
  if (agent.program_pid <= 0) {
    errno = ESRCH;
    return -1;
  }

  if (kill(agent.program_pid, SIGKILL) < 0 && errno != ESRCH) return -1;

  return 0;
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
  return uav_agent_proto_send_exit(agent.transport, status);
}

static int uav_agent_dispatch(const struct uav_proto_msg* msg) {
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

    case UAV_AGENT_MSG_EXIT:
      if (msg->header.length != 0) {
        errno = EPROTO;
        return -1;
      }
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

    /* Check child exit periodically, but block fully while idle. */
    timeout = agent.program_pid > 0 ? 100 : -1;

    do {
      ret = poll(&fd, 1, timeout);
    } while (ret < 0 && errno == EINTR);

    if (ret < 0) return -1;
    if (ret == 0) continue;

    if (fd.revents & POLLIN) {
      if (uav_agent_proto_recv(agent.transport, &msg) < 0) return -1;

      ret = uav_agent_dispatch(&msg);
      if (ret < 0) return -1;
      if (ret > 0) return 0;
    }

    if (fd.revents & (POLLERR | POLLHUP | POLLNVAL)) {
      errno = ECONNRESET;
      return -1;
    }
  }
}

int main(int argc, char* argv[]) {
  int ret;

  ret = uav_agent_parse_options(argc, argv);
  if (ret > 0) return EXIT_SUCCESS;
  if (ret < 0) {
    print_help();
    return EXIT_FAILURE;
  }

  if (uav_agent_setup() < 0) {
    int saved_errno = errno;
    uav_agent_send_error(saved_errno);
    fprintf(stderr, "[UAV-AGENT] setup failed: %s\n", strerror(saved_errno));
    uav_agent_cleanup();
    return EXIT_FAILURE;
  }

  if (uav_agent_loop() < 0) {
    int saved_errno = errno;
    uav_agent_send_error(saved_errno);
    fprintf(stderr, "[UAV-AGENT] protocol loop failed: %s\n",
            strerror(saved_errno));
    uav_agent_cleanup();
    return EXIT_FAILURE;
  }

  uav_agent_cleanup();
  return EXIT_SUCCESS;
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
