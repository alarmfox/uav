#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <linux/limits.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "config.h"
#include "utils.h"

static int uavd_remove_sandbox_cgroup(const char* root, const char* name);
static int uavd_is_sandbox_cgroup(const char* name);
static int uavd_remove_cgroup(const char *path);

int uavd_init_cgroup_hierarchy(void) {
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

int uavd_cleanup_cgroup_hierarchy(void) {
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

int uavd_add_pid_to_cgroup(const char* cgroup, pid_t pid) {
  char path[PATH_MAX];
  char buffer[32];

  snprintf(path, sizeof(path), "%s/cgroup.procs", cgroup);
  snprintf(buffer, sizeof(buffer), "%d", pid);

  return uav_write_file(path, (const unsigned char*)buffer, strlen(buffer));
}

static int uavd_remove_sandbox_cgroup(const char* root, const char* name) {
  static const unsigned char kill_value[] = "1";
  char path[PATH_MAX];

  if (snprintf(path, sizeof(path), "%s/%s/cgroup.kill", root, name) >=
      (int)sizeof(path)) {
    errno = ENAMETOOLONG;
    return -1;
  }

  if (uav_write_file(path, kill_value, sizeof(kill_value) - 1) < 0 &&
      errno != ENOENT) {
    fprintf(stderr, "[UAVD] failed to kill cgroup %s: %s\n", name,
            strerror(errno));
    return -1;
  }

  if (snprintf(path, sizeof(path), "%s/%s/workload", root, name) >=
      (int)sizeof(path)) {
    errno = ENAMETOOLONG;
    return -1;
  }
  if (uavd_remove_cgroup(path) < 0) return -1;

  if (snprintf(path, sizeof(path), "%s/%s/agent", root, name) >=
      (int)sizeof(path)) {
    errno = ENAMETOOLONG;
    return -1;
  }
  if (uavd_remove_cgroup(path) < 0) return -1;

  if (snprintf(path, sizeof(path), "%s/%s", root, name) >= (int)sizeof(path)) {
    errno = ENAMETOOLONG;
    return -1;
  }

  return uavd_remove_cgroup(path);
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

static int uavd_remove_cgroup(const char* path) {
  return rmdir(path)< 0 || errno != ENOENT;
}
