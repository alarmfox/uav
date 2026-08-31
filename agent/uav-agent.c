#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <limits.h>
#include <poll.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <termios.h>
#include <unistd.h>

#include "sandbox_protocol.h"
#include "utils.h"

#define UAV_AGENT_DIR "/run/uav"
#define UAV_AGENT_PROGRAM_TEMPLATE UAV_AGENT_DIR "/uav_program_XXXXXX"

struct uav_agent_state {
  int control_fd;
  pid_t program_pid;
  bool program_ready;
  char program_path[PATH_MAX];
};

static struct uav_agent_state agent = {
    .control_fd = -1,
    .program_pid = -1,
    .program_ready = false,
    .program_path = {0},
};

static void print_help(void);
static int uav_agent_parse_options(int argc, char* const argv[]);
static int uav_agent_setup(void);
static void uav_agent_cleanup(void);
static int uav_agent_loop(void);
static int uav_agent_dispatch(const struct uav_sandbox_proto_msg* msg);
static int uav_agent_upload(const struct uav_sandbox_proto_msg* begin);
static int uav_agent_run(const struct uav_sandbox_proto_msg* msg);
static int uav_agent_kill(void);
static int uav_agent_check_program(void);
static int uav_agent_send_error(int error);

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

  if (mkdir(UAV_AGENT_DIR, 0700) < 0 && errno != EEXIST) return -1;

  /* Setup is complete. The host may start sending commands. */
  return uav_sandbox_proto_send(agent.control_fd, UAV_SANDBOX_MSG_READY, NULL,
                                0);
}

static void uav_agent_cleanup(void) {
  if (agent.program_pid > 0) {
    int status;

    kill(agent.program_pid, SIGKILL);
    while (waitpid(agent.program_pid, &status, 0) < 0 && errno == EINTR) {
    }
    agent.program_pid = -1;
  }

  if (agent.control_fd >= 0) {
    close(agent.control_fd);
    agent.control_fd = -1;
  }

  if (agent.program_ready) {
    unlink(agent.program_path);
    agent.program_ready = false;
    agent.program_path[0] = '\0';
  }
}

static int uav_agent_send_error(int error) {
  uint32_t payload = htonl((uint32_t)error);

  if (agent.control_fd < 0) return -1;

  return uav_sandbox_proto_send(agent.control_fd, UAV_SANDBOX_MSG_ERROR,
                                &payload, sizeof(payload));
}

static int uav_agent_upload(const struct uav_sandbox_proto_msg* begin) {
  char path[] = UAV_AGENT_PROGRAM_TEMPLATE;
  uint8_t* data = NULL;
  size_t size = 0;
  int fd = -1;
  int flags;
  int saved_errno;
  int ret = -1;

  if (agent.program_pid > 0) {
    errno = EBUSY;
    return -1;
  }

  /* mkstemp gives every uploaded file a private, unpredictable pathname. */
  fd = mkstemp(path);
  if (fd < 0) goto out;

  flags = fcntl(fd, F_GETFD);
  if (flags < 0 || fcntl(fd, F_SETFD, flags | FD_CLOEXEC) < 0) goto out;

  if (uav_sandbox_proto_download(agent.control_fd, begin, path, &data, &size) <
      0)
    goto out;

  if (uav_write_all(fd, data, size) < 0) goto out;

  if (fchmod(fd, 0700) < 0) goto out;

  if (close(fd) < 0) {
    fd = -1;
    goto out;
  }
  fd = -1;

  if (agent.program_ready) unlink(agent.program_path);

  strcpy(agent.program_path, path);
  agent.program_ready = true;
  ret = 0;

out:
  saved_errno = errno;
  if (fd >= 0) close(fd);
  if (ret < 0) unlink(path);
  free(data);
  errno = saved_errno;
  return ret;
}

static int uav_agent_run(const struct uav_sandbox_proto_msg* msg) {
  size_t path_size;
  pid_t pid;

  if (!agent.program_ready) {
    errno = ENOENT;
    return -1;
  }

  if (agent.program_pid > 0) {
    errno = EBUSY;
    return -1;
  }

  path_size = strlen(agent.program_path) + 1;
  if (msg->length != path_size ||
      memcmp(msg->payload, agent.program_path, path_size) != 0) {
    errno = EPROTO;
    return -1;
  }

  pid = fork();
  if (pid < 0) return -1;

  if (pid == 0) {
    char* const argv[] = {agent.program_path, NULL};
    char* const envp[] = {NULL};

    /* The analyzed program must not inherit the agent's control channel. */
    close(agent.control_fd);

    execve(agent.program_path, argv, envp);
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
  uint32_t payload;
  pid_t pid;
  int status;

  if (agent.program_pid <= 0) return 0;

  do {
    pid = waitpid(agent.program_pid, &status, WNOHANG);
  } while (pid < 0 && errno == EINTR);

  if (pid == 0) return 0;
  if (pid < 0) return -1;

  agent.program_pid = -1;
  payload = htonl((uint32_t)status);

  return uav_sandbox_proto_send(agent.control_fd, UAV_SANDBOX_MSG_EXIT,
                                &payload, sizeof(payload));
}

static int uav_agent_dispatch(const struct uav_sandbox_proto_msg* msg) {
  switch (msg->type) {
    case UAV_SANDBOX_MSG_UPLOAD_BEGIN:
      return uav_agent_upload(msg);

    case UAV_SANDBOX_MSG_RUN:
      return uav_agent_run(msg);

    case UAV_SANDBOX_MSG_KILL:
      if (msg->length != 0) {
        errno = EPROTO;
        return -1;
      }
      return uav_agent_kill();

    case UAV_SANDBOX_MSG_EXIT:
      if (msg->length != 0) {
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
  struct uav_sandbox_proto_msg msg;
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
      if (uav_sandbox_proto_recv(agent.control_fd, &msg) < 0) return -1;

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
