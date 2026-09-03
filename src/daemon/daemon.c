#include <ctype.h>
#include <dirent.h>
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

static int uavd_remove_cgroup(const char* path) {
  if (rmdir(path) == 0 || errno == ENOENT) return 0;

  fprintf(stderr, "[UAVD] failed to remove cgroup %s: %s\n", path,
          strerror(errno));
  return -1;
}

static int uavd_is_sandbox_cgroup(const char* name) {
  static const char prefix[] = "sandbox-";
  const unsigned char* digit;

  if (strncmp(name, prefix, sizeof(prefix) - 1) != 0) return 0;

  digit = (const unsigned char*)name + sizeof(prefix) - 1;
  if (*digit == '\0') return 0;

  while (*digit != '\0') {
    if (!isdigit(*digit)) return 0;
    ++digit;
  }

  return 1;
}

static int uavd_remove_sandbox_cgroup(const char* root, const char* name) {
  static const unsigned char kill_value[] = "1";
  char path[PATH_MAX];
  int ret = 0;

  if (snprintf(path, sizeof(path), "%s/%s/cgroup.kill", root, name) >=
      (int)sizeof(path)) {
    errno = ENAMETOOLONG;
    return -1;
  }

  if (uav_write_file(path, kill_value, sizeof(kill_value) - 1) < 0 &&
      errno != ENOENT) {
    fprintf(stderr, "[UAVD] failed to kill cgroup %s: %s\n", name,
            strerror(errno));
    ret = -1;
  }

  if (snprintf(path, sizeof(path), "%s/%s/workload", root, name) >=
      (int)sizeof(path)) {
    errno = ENAMETOOLONG;
    return -1;
  }
  if (uavd_remove_cgroup(path) < 0) ret = -1;

  if (snprintf(path, sizeof(path), "%s/%s/agent", root, name) >=
      (int)sizeof(path)) {
    errno = ENAMETOOLONG;
    return -1;
  }
  if (uavd_remove_cgroup(path) < 0) ret = -1;

  if (snprintf(path, sizeof(path), "%s/%s", root, name) >= (int)sizeof(path)) {
    errno = ENAMETOOLONG;
    return -1;
  }
  if (uavd_remove_cgroup(path) < 0) ret = -1;

  return ret;
}

static int uavd_cleanup_cgroup_hierarchy(void) {
  static const char root[] = "/sys/fs/cgroup/" UAV_UAVD_ROOT_CGROUP_NAME;
  char path[PATH_MAX];
  char pid[32];
  struct dirent* entry;
  DIR* directory;
  int ret = 0;
  int saved_errno;

  directory = opendir(root);
  if (directory == NULL) return errno == ENOENT ? 0 : -1;

  errno = 0;
  while ((entry = readdir(directory)) != NULL) {
    if (!uavd_is_sandbox_cgroup(entry->d_name)) continue;
    if (uavd_remove_sandbox_cgroup(root, entry->d_name) < 0) ret = -1;
    errno = 0;
  }
  if (errno != 0) ret = -1;

  saved_errno = errno;
  if (closedir(directory) < 0) ret = -1;
  if (ret < 0 && saved_errno != 0) errno = saved_errno;

  snprintf(pid, sizeof(pid), "%d", getpid());
  if (uav_write_file("/sys/fs/cgroup/cgroup.procs", (const unsigned char*)pid,
                     strlen(pid)) < 0) {
    fprintf(stderr, "[UAVD] failed to leave cgroup hierarchy: %s\n",
            strerror(errno));
    ret = -1;
  }

  if (snprintf(path, sizeof(path), "%s/daemon", root) >= (int)sizeof(path)) {
    errno = ENAMETOOLONG;
    return -1;
  }
  if (uavd_remove_cgroup(path) < 0) ret = -1;
  if (uavd_remove_cgroup(root) < 0) ret = -1;

  return ret;
}

static int uavd_init_cgroup_hierarchy(void) {
  char path[PATH_MAX];
  char controllers[64];
  int ret = -1;

  /* Create root sandbox cgroup. The cgroup will have this structure
   *
   * /uav
   * --/daemon
   * --/sandbox-<id>
   * ----/agent
   * ----/workload
   * */

  /* Create root cgroup and uavd dedicated cgroup */
  snprintf(path, sizeof(path), "/sys/fs/cgroup/%s", UAV_UAVD_ROOT_CGROUP_NAME);
  ret = mkdir(path, 0755);
  if (ret != 0 && errno != EEXIST) return ret;

  snprintf(path, sizeof(path), "/sys/fs/cgroup/%s/daemon",
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
  snprintf(buffer, sizeof(buffer), "%d", pid);

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
  int passcred_opt = 1;
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

  fd = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);
  if (fd < 0) {
    fprintf(stderr, "[UAVD] failed to create socket: %s\n", strerror(errno));
    goto cleanup;
  }

  /* Accepted sockets must collect credentials before clients can send. */
  if (setsockopt(fd, SOL_SOCKET, SO_PASSCRED, &passcred_opt,
                 sizeof(passcred_opt)) < 0) {
    fprintf(stderr, "[UAVD] failed to enable credentials: %s\n",
            strerror(errno));
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

  /* Move ourselves to uav/daemoncgroup */
  ret = uavd_add_pid_to_cgroup("daemon", getpid());
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

static int handle_register_workload(pid_t pid) {
  char cgroup[64];

  if (snprintf(cgroup, sizeof(cgroup), "sandbox-%" PRIu64 "/workload",
               uavd.sandbox.id) >= (int)sizeof(cgroup)) {
    errno = ENAMETOOLONG;
    return -1;
  }

  return uavd_add_pid_to_cgroup(cgroup, pid);
}

static int handle_client(int fd) {
  int ret = -1;
  int request_error;
  int saved_errno;
  struct uav_proto_msg msg;
  struct ucred peer_creds, sender_creds;
  socklen_t len = sizeof(sender_creds);

  ret = getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &peer_creds, &len);
  if (ret != 0) {
    fprintf(stderr, "[UAVD] error: failed to get credentials\n");
    goto cleanup;
  }

  printf("[UAVD] connected client pid=%d uid=%d gid=%d\n", peer_creds.pid,
         peer_creds.uid, peer_creds.gid);

  while (1) {
    ret = uav_daemon_proto_receive_request(fd, &msg, &sender_creds);
    if (ret != 0) goto cleanup;

    request_error = 0;
    switch (msg.type) {
      case UAV_DAEMON_MSG_REGISTER_AGENT:
        /*
         * Initial registration must come from the process that established
         * the connection.
         */
        if (sender_creds.pid != peer_creds.pid)
          request_error = EACCES;
        else
          request_error =
              handle_register_agent(sender_creds.pid) < 0 ? errno : 0;
        break;

      case UAV_DAEMON_MSG_REGISTER_WORKLOAD:
        request_error =
            handle_register_workload(sender_creds.pid) < 0 ? errno : 0;
        break;
      default:
        request_error = EPROTO;
        break;
    }

    if (uav_daemon_proto_send_response(fd, msg.type, request_error, NULL, 0) <
        0)
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
  int initialized = 0;
  int ret = 1;

  signal(SIGINT, &on_shutdown_requested);
  signal(SIGTERM, &on_shutdown_requested);

  ret = uavd_init();
  if (ret != 0) {
    fprintf(stderr, "[UAVD] cannot init: %s\n", strerror(errno));
    goto cleanup;
  }
  initialized = 1;
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

  if (initialized && uavd_cleanup_cgroup_hierarchy() < 0) {
    fprintf(stderr, "[UAVD] failed to clean up cgroup hierarchy\n");
    ret = -1;
  }

  if (ret != 0)
    ret = EXIT_FAILURE;
  else
    ret = EXIT_SUCCESS;

  return ret;
}
