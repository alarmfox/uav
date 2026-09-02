#include <errno.h>
#include <inttypes.h>
#include <poll.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

#include "config.h"
#include "daemon_protocol.h"
#include "transport.h"
#include "utils.h"

#define UAVD_BACKLOG 1

struct uavd_sandbox_state {
  int sandbox_cgroup_fd;
  int agent_cgroup_fd;
  int workload_cgroup_fd;
  uint64_t id;
};

struct uavd_state {
  int socket_fd;
  struct uavd_sandbox_state sandbox;
};

static struct uavd_state uavd = {
    .socket_fd = -1,
    .sandbox = (struct uavd_sandbox_state){.sandbox_cgroup_fd = -1,
                                           .agent_cgroup_fd = -1,
                                           .workload_cgroup_fd = -1,
                                           .id = 0UL}};

static int g_shutdown_requested = 0;
static void on_shutdown_requested(int signal_number) {
  (void)signal_number;
  __atomic_store_n(&g_shutdown_requested, 1, __ATOMIC_RELAXED);
}

static int uavd_init_cgroup_hierarchy(void) {
  char path[PATH_MAX];
  char controllers[64];
  int ret = -1;

  /* Create root cgroup and uavd dedicated cgroup */
  snprintf(path, sizeof(path), "/sys/fs/cgroup/%s", UAV_UAVD_ROOT_CGROUP_NAME);
  ret = mkdir(path, 0755);
  if (ret != 0 && errno != EEXIST) return ret;

  snprintf(path, sizeof(path), "/sys/fs/cgroup/%s/uavd",
           UAV_UAVD_ROOT_CGROUP_NAME);
  ret = mkdir(path, 0755);
  if (ret != 0 && errno != EEXIST) return ret;

  strcpy(controllers, "+cpu +memory +pids");
  /* Write to parent's subtree_control to enable controllers for children. We
   * need to enable this for root cgroup too since it is proprietary */
  strcpy(path, "/sys/fs/cgroup/cgroup.subtree_control");
  ret = uav_write_file(path, (const unsigned char*)controllers,
                       strlen(controllers));
  if (ret != 0 && errno != EEXIST) return ret;

  snprintf(path, sizeof(path), "/sys/fs/cgroup/%s/cgroup.subtree_control",
           UAV_UAVD_ROOT_CGROUP_NAME);
  ret = uav_write_file(path, (const unsigned char*)controllers,
                       strlen(controllers));

  return (ret != 0 && errno != EEXIST) ? ret : 0;
}

static int uavd_add_pid_to_cgroup(const char* cgroup, pid_t pid) {
  char path[PATH_MAX];
  char buffer[32];

  snprintf(path, sizeof(path), "/sys/fs/cgroup/%s/%s/cgroup.procs",
           UAV_UAVD_ROOT_CGROUP_NAME, cgroup);
  snprintf(buffer, sizeof(buffer), "%d\n", pid);

  return uav_write_file(path, (const unsigned char*)buffer, strlen(buffer));
}

static int uavd_remove_stale_socket(const char* path) {
  struct stat st;

  if (lstat(path, &st) < 0) return errno == ENOENT ? 0 : -1;

  /* Do not blindly delete an unexpected regular file. */
  if (!S_ISSOCK(st.st_mode)) {
    errno = EEXIST;
    return -1;
  }

  return unlink(path);
}

static int uavd_setup_runtime_dir(void) {
  struct stat st;
  int ret;

  ret = mkdir(UAV_UAVD_RUNTIME_DIR, 0755);
  if (ret < 0 && errno != EEXIST) return -1;

  /*
   * Reject an attacker-created directory or symlink.
   * chmod() is safe only after ownership and type are verified.
   */
  ret = lstat(UAV_UAVD_RUNTIME_DIR, &st);
  if (ret < 0) return -1;

  if (!S_ISDIR(st.st_mode) || st.st_uid != 0 ||
      (st.st_mode & (S_IWGRP | S_IWOTH)) != 0) {
    errno = EPERM;
    return -1;
  }

  return chmod(UAV_UAVD_RUNTIME_DIR, 0755);
}

static int uavd_setup_socket(void) {
  const char* path = UAV_UAVD_CONTROL_PATH;
  mode_t previous_umask;
  socklen_t address_len;
  size_t path_len;
  int bound = 0;
  int fd = -1;
  int ret = -1;
  int saved_errno;
  struct sockaddr_un address;

  path_len = strlen(path);
  if (path_len >= sizeof(address.sun_path)) {
    errno = ENAMETOOLONG;
    fprintf(stderr, "[UAVD] control socket path is too long\n");
    goto cleanup;
  }

  if (uavd_setup_runtime_dir() < 0) {
    fprintf(stderr, "[UAVD] failed to prepare runtime directory: %s\n",
            strerror(errno));
    goto cleanup;
  }

  if (uavd_remove_stale_socket(path) < 0) {
    fprintf(stderr, "[UAVD] failed to remove stale socket: %s\n",
            strerror(errno));
    goto cleanup;
  }

  fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
  if (fd < 0) {
    fprintf(stderr, "[UAVD] failed to create socket: %s\n", strerror(errno));
    goto cleanup;
  }

  memset(&address, 0, sizeof(address));
  address.sun_family = AF_UNIX;
  memcpy(address.sun_path, path, path_len + 1);
  address_len =
      (socklen_t)(offsetof(struct sockaddr_un, sun_path) + path_len + 1);

  previous_umask = umask(0177);
  ret = bind(fd, (struct sockaddr*)&address, address_len);
  saved_errno = errno;
  umask(previous_umask);
  errno = saved_errno;
  if (ret < 0) {
    fprintf(stderr, "[UAVD] failed to bind socket: %s\n", strerror(errno));
    goto cleanup;
  }
  bound = 1;

  ret = chmod(path, 0666);
  if (ret < 0) {
    fprintf(stderr, "[UAVD] failed to chmod socket: %s\n", strerror(errno));
    goto cleanup;
  }

  ret = listen(fd, UAVD_BACKLOG);
  if (ret < 0) {
    fprintf(stderr, "[UAVD] failed to enter listen mode: %s\n",
            strerror(errno));
    goto cleanup;
  }

  ret = 0;
  uavd.socket_fd = fd;
  fd = -1;
cleanup:
  if (ret != 0) {
    saved_errno = errno;
    if (fd >= 0) close(fd);
    if (bound) unlink(path);
    errno = saved_errno;
  }
  return ret;
}

static int uavd_init(void) {
  int ret;

  ret = uavd_init_cgroup_hierarchy();
  if (ret != 0) return ret;

  /* Move ourselves to uav/uavd cgroup */
  ret = uavd_add_pid_to_cgroup("uavd", getpid());
  if (ret != 0) return ret;

  ret = uavd_setup_socket();
  if (ret != 0) return ret;

  return 0;
}

static int handle_register_agent(pid_t pid) {
  int ret = -1;
  char path[PATH_MAX];
  char cgroup[64];
  uint64_t id;

  if (uavd.sandbox.id == UINT64_MAX) {
    errno = EOVERFLOW;
    return -1;
  }
  id = ++uavd.sandbox.id;
  if (snprintf(cgroup, sizeof(cgroup), "sandbox-%" PRIu64, id) >=
      (int)sizeof(cgroup)) {
    errno = ENAMETOOLONG;
    return -1;
  }

  /* Create root sandbox cgroup. The cgroup will have this structure
   *
   * /uav
   * --/uavd
   * --/sandbox-<id>
   * ----/agent
   * ----/workload
   * */
  snprintf(path, sizeof(path), "/sys/fs/cgroup/%s/%s",
           UAV_UAVD_ROOT_CGROUP_NAME, cgroup);
  ret = mkdir(path, 0755);
  if (ret != 0) return ret;

  snprintf(path, sizeof(path), "/sys/fs/cgroup/%s/%s/agent",
           UAV_UAVD_ROOT_CGROUP_NAME, cgroup);
  ret = mkdir(path, 0755);
  if (ret != 0) return ret;

  snprintf(path, sizeof(path), "/sys/fs/cgroup/%s/%s/workload",
           UAV_UAVD_ROOT_CGROUP_NAME, cgroup);
  ret = mkdir(path, 0755);
  if (ret != 0) return ret;

  snprintf(path, sizeof(path), "%s/agent", cgroup);

  return uavd_add_pid_to_cgroup(path, pid);
}

static int handle_register_workload(void) { return 0; }

static int handle_client(int fd) {
  int ret = -1;
  int request_error;
  int saved_errno;
  int passcred_opt = 1;
  struct uav_transport* transport = NULL;
  struct uav_proto_msg msg;
  struct ucred creds;
  socklen_t len = sizeof(creds);

  ret = setsockopt(fd, SOL_SOCKET, SO_PASSCRED, &passcred_opt, sizeof(int));
  if (ret != 0) {
    fprintf(stderr, "[UAVD] error: failed to set SO_PASSCRED\n");
    goto cleanup;
  }

  ret = getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &creds, &len);
  if (ret != 0) {
    fprintf(stderr, "[UAVD] error: failed to get credentials\n");
    goto cleanup;
  }

  transport = uav_fd_transport_create(fd);
  if (transport == NULL) goto cleanup;
  fd = -1;

  printf("[UAVD] connected client pid=%d uid=%d gid=%d\n", creds.pid, creds.uid,
         creds.gid);

  while (1) {
    ret = uav_daemon_proto_recv(transport, &msg);
    if (ret != 0) goto cleanup;

    request_error = 0;
    if (msg.header.kind != UAV_PROTO_REQUEST) {
      request_error = EPROTO;
    } else {
      switch (msg.header.type) {
        case UAV_DAEMON_MSG_REGISTER_AGENT:
          if (msg.header.length != 0)
            request_error = EPROTO;
          else if (handle_register_agent(creds.pid) < 0)
            request_error = errno;
          break;
        case UAV_DAEMON_MSG_REGISTER_WORKLOAD:
          if (msg.header.length != 0)
            request_error = EPROTO;
          else if (handle_register_workload() < 0)
            request_error = errno;
          break;
        default:
          request_error = EPROTO;
          break;
      }
    }

    if (uav_daemon_proto_send_response(transport, msg.header.type,
                                       request_error, NULL, 0) < 0)
      goto cleanup;

    /* A protocol or operation failure leaves daemon state non-retryable. */
    if (request_error != 0) {
      errno = request_error;
      ret = -1;
      goto cleanup;
    }
  }
  ret = 0;

cleanup:
  saved_errno = errno;
  if (transport != NULL) uav_transport_destroy(&transport);
  if (fd >= 0) close(fd);
  errno = saved_errno;

  return ret;
}

static int uavd_loop(void) {
  int ret;
  int client_fd;

  while (!__atomic_load_n(&g_shutdown_requested, __ATOMIC_RELAXED)) {
    struct pollfd pfd = {uavd.socket_fd, POLLIN, 0};
    ret = poll(&pfd, 1, 1000);

    if (ret > 0) {
      client_fd = accept(uavd.socket_fd, NULL, NULL);
      if (client_fd < 0) continue;

      handle_client(client_fd);
    }
  }
  return 0;
}

int main(void) {
  int ret = 1;

  signal(SIGINT, &on_shutdown_requested);
  signal(SIGTERM, &on_shutdown_requested);

  ret = uavd_init();
  if (ret != 0) {
    fprintf(stderr, "[UAVD] cannot init: %s\n", strerror(errno));
    goto cleanup;
  }
  printf("[UAVD] ready. Listening on %s\n", UAV_UAVD_CONTROL_PATH);

  ret = uavd_loop();
  if (ret != 0) {
    fprintf(stderr, "[UAVD] loop failed: %s\n", strerror(errno));
    goto cleanup;
  }
  ret = 0;

cleanup:
  if (uavd.socket_fd >= 0) {
    close(uavd.socket_fd);
    uavd.socket_fd = -1;
    unlink(UAV_UAVD_CONTROL_PATH);
  }

  if (ret != 0)
    ret = EXIT_FAILURE;
  else
    ret = EXIT_SUCCESS;

  return ret;
}
