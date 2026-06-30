#ifndef __UAV_MONITOR_UAV
#define __UAV_MONITOR_UAV

#ifndef __BPF__
/* Userspace needs linux types */
#include <linux/types.h>
#endif
/* eBPF gets types from vmlinux.h automatically */

#define UAV_CGROUP_POLICY_BLOCK 0
#define UAV_CGROUP_POLICY_LOG 1

struct sensitive_file {
  __u64 inode;
  __s32 read_weight;
  __s32 write_weight;
  __s32 chmod_weight;
  __s32 unlink_weight;
  __u32 flags;
};

/* Explains what to do with when suspicion_index reaches a certain value */
struct cgroup_policy {
  /* What to do when threshold is set */
  __u32 mode;
  __s32 threshold;
};

/* Process tree tracking */
struct process_metadata {
  /* This is needed when kernel reusees pids */
  __u64 start_time;
  __u32 parent_tgid;
  __u64 cgroup_id;
  __s32 inherited_score;
};
#endif // !__UAV_MONITOR_UAV
