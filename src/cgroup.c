#include <errno.h>
#include <fcntl.h>
#include <linux/stat.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "cgroup.h"

/* Enable controllers in the parent cgroup so they're available to children */
static int enable_controllers(const char *parent_cgroup, const char *controllers) {
  char path[512];
  int fd, ret;

  /* Write to parent's subtree_control to enable controllers for children */
  snprintf(path, sizeof(path), "/sys/fs/cgroup/%s/cgroup.subtree_control", parent_cgroup);

  fd = open(path, O_WRONLY);
  if (fd < 0) {
    fprintf(stderr, "[SANDBOX] cannot open %s: %s\n", path, strerror(errno));
    return -1;
  }

  ret = write(fd, controllers, strlen(controllers));
  close(fd);

  if (ret < 0) {
    fprintf(stderr, "[SANDBOX] cannot enable controllers: %s\n", strerror(errno));
    return -1;
  }

  return 0;
}

/* Create a new cgroup in /sys/fs/cgroup (assume we have cgroup v2). This functions does not return 
 * an error if the cgroup alreay exists */
int cgroup_create(const char *cgname) {
  char path[256];
  int ret;

  snprintf(path, sizeof(path), "/sys/fs/cgroup/%s", cgname);
  ret = mkdir(path, 0755);

  if (ret != 0 && errno != EEXIST) return ret;

  /* Enable controllers in ROOT cgroup for our child cgroup */
  /* Format: "+controller1 +controller2 +controller3" */
  ret = enable_controllers("", "+cpu +memory +pids +io");
  if (ret != 0) {
    fprintf(stderr, "[SANDBOX] cannot enable controllers in root\n");
    return ret;
  }

  return 0;
}

/* The kernel exposes the cgroup ID as stx_ino when querying a cgroup directory. */
unsigned long cgroup_getid(const char *cgname) {
  struct statx stx;
  char path[256];

  snprintf(path, sizeof(path), "/sys/fs/cgroup/%s", cgname);

  if (statx(AT_FDCWD, path, 0, STATX_INO, &stx) < 0) {
    perror("statx");
    return 0;
  }

  return stx.stx_ino;
}

/* Moves `pid` to cgroup `cgname`. Assume that the cgroup exists. */
int cgroup_add_pid(const char *cgname, pid_t pid) {
  char path[256];
  int fd;
  char buf[32];

  snprintf(path, sizeof(path), "/sys/fs/cgroup/%s/cgroup.procs", cgname);

  fd = open(path, O_WRONLY);
  if (fd < 0) return -1;

  snprintf(buf, sizeof(buf), "%d", pid);
  write(fd, buf, strlen(buf));
  close(fd);
  return 0;
}

/* Set limits (memory, CPU and I/O) to the cgroup */
int cgroup_set_limits(const char *cgname, const struct uav_cgroup_limits *limits) {
  char path[512];
  int fd, ret;
  char buf[64];

  /* Set memory limit */
  snprintf(path, sizeof(path), "/sys/fs/cgroup/%s/memory.max", cgname);
  fd = open(path, O_WRONLY);
  if (fd < 0) {
    fprintf(stderr, "[SANDBOX] cannot open %s: %s\n", path, strerror(errno));
    return -1;
  }

  snprintf(buf, sizeof(buf), "%zu", limits->memory_max);
  ret = write(fd, buf, strlen(buf));
  close(fd);
  if (ret < 0) return -1;

  /* Set CPU limit (cpu.max format: "$MAX $PERIOD") */
  snprintf(path, sizeof(path), "/sys/fs/cgroup/%s/cpu.max", cgname);
  fd = open(path, O_WRONLY);
  if (fd < 0) return -1;
  snprintf(buf, sizeof(buf), "%zu 100000", limits->cpu_max);
  ret = write(fd, buf, strlen(buf));
  close(fd);
  if (ret < 0) return -1;

  /* Set pid limit */
  snprintf(path, sizeof(path), "/sys/fs/cgroup/%s/pids.max", cgname);
  fd = open(path, O_WRONLY);
  if (fd < 0) return -1;
  snprintf(buf, sizeof(buf), "%zu", limits->pids_max);
  ret = write(fd, buf, strlen(buf));
  close(fd);
  if (ret < 0) return -1;

  return 0;
}
