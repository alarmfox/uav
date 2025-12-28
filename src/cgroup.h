#ifndef __UAV_CGROUP_H
#define __UAV_CGROUP_H

#include <sys/types.h>

/* Limits that can be configured on a single sandbox  */
struct uav_cgroup_limits {
  /* Maximum amount of memory that can be used by the sandbox (bytes)*/
  size_t memory_max;
  /* Maximum amount of CPU that can be used by the sandbox (% of a period) */
  size_t cpu_max;
  /* Maximum amount of pids (processes) into the sandbox */
  size_t pids_max;
  /* Stack size*/
  size_t stack_size;
  /* Tmpfs size  */
  size_t tmpfs_size;
};

int cgroup_create(const char *cgname);
unsigned long get_cgroup_id(const char *cgname);
int cgroup_add_pid(const char *cgname, pid_t pid);
int cgroup_set_limits(const char *cgname, const struct uav_cgroup_limits *limits);

#endif // !__UAV_CGROUP_H
