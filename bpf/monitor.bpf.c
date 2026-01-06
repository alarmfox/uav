#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "monitor_types.h"

#define MAY_EXEC   0x00000001
#define MAY_WRITE  0x00000002
#define MAY_READ   0x00000004
#define MAY_APPEND 0x00000008

#define EPERM 1

/* Map up to 1024 cgroups. Each cgroup has policy. For example we just log sandbox cgroup */
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 1024);
  __type(key, __u64);    // cgroup_id
  __type(value, struct cgroup_policy);
} cgroup_policies SEC(".maps");

/* Map: inode -> sensitivity config */
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 10000);
  __type(key, __u64);
  __type(value, struct sensitive_file);
} sensitive_inodes SEC(".maps");

/* Track per process metadata */
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 10000);
  __type(key, __u32);
  __type(value, struct process_metadata);
} process_tree SEC(".maps");

/* Information about suspicion_state */
struct suspicion_state {
  __s32 own_score;
  __u64 event_count;
  __u64 last_update_ns;
};

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 10000);
  __type(key, __u32);
  __type(value, struct suspicion_state);
} process_suspicion SEC(".maps");

SEC("tp/sched/sched_process_fork")
int trace_fork(struct trace_event_raw_sched_process_fork *ctx) {
  __u32 parent_tgid = ctx->parent_pid;
  __u32 child_tgid = ctx->child_pid;
  __u64 cgid = bpf_get_current_cgroup_id();

  /* Get parent's current state */
  struct suspicion_state *parent_state = bpf_map_lookup_elem(&process_suspicion, &parent_tgid);

  /* Create child metadata */
  struct process_metadata child_meta = {
    .parent_tgid = parent_tgid,
    .cgroup_id = cgid,
    .start_time = bpf_ktime_get_ns(),
    .inherited_score = parent_state ? parent_state->own_score : 0.0,
  };
  bpf_map_update_elem(&process_tree, &child_tgid, &child_meta, BPF_ANY);

  /* Initialize child suspicion (starts with inherited score) */
  struct suspicion_state child_state = {
    .own_score = child_meta.inherited_score,
    .event_count = 0,
    .last_update_ns = bpf_ktime_get_ns(),
  };
  bpf_map_update_elem(&process_suspicion, &child_tgid, &child_state, BPF_ANY);
  bpf_printk("sched\n");

  return 0;
}

SEC("tp/sched/sched_process_exit")
int trace_exit(struct trace_event_raw_sched_process_template *ctx) {
  __u32 tgid = ctx->pid;

  // Cleanup maps
  bpf_map_delete_elem(&process_suspicion, &tgid);
  bpf_map_delete_elem(&process_tree, &tgid);

  return 0;
}

SEC("lsm/file_permission")
int BPF_PROG(file_permission, struct file *file, int mask) {
  __u64 pid_tgid = bpf_get_current_pid_tgid();
  __u32 tgid = pid_tgid >> 32;
  __u64 cgid = bpf_get_current_cgroup_id();
  __s64 increment = 0;
  __s64 total_score;
  struct sensitive_file *sens = NULL;
  struct cgroup_policy *policy = NULL;
  struct suspicion_state *state = NULL;
  struct process_metadata *meta = NULL;
  struct inode *inode = NULL;

  /* Check cgroup policy */
  policy =  bpf_map_lookup_elem(&cgroup_policies, &cgid);
  if (!policy) {
    /* Fallback to default poliicy */
    __u64 default_key = 0;
    policy = bpf_map_lookup_elem(&cgroup_policies, &default_key);
    if (!policy) return 0;
  }

  /* Get current process suspicion */
  state = bpf_map_lookup_elem(&process_suspicion, &tgid);
  if (!state) {
    // First time seeing this process, initialize
    struct suspicion_state new_state = {0};
    bpf_map_update_elem(&process_suspicion, &tgid, &new_state, BPF_ANY);
    state = bpf_map_lookup_elem(&process_suspicion, &tgid);
    if (!state) return 0;
  }

  /* Check if file is sensitive */
  inode = BPF_CORE_READ(file, f_inode);
  __u64 ino = BPF_CORE_READ(inode, i_ino);

  sens = bpf_map_lookup_elem(&sensitive_inodes, &ino);
  if (!sens)
    return 0;

  /* Calculate increment */
  if (mask & MAY_READ) increment += sens->read_weight;

  if (mask & MAY_WRITE) increment += sens->write_weight;

  if (mask & MAY_APPEND) increment += sens->write_weight;

  /* Update this process's own score */
  state->own_score += increment;
  state->event_count++;

  /* Calculate total suspicion (own + inherited) */
  meta = bpf_map_lookup_elem(&process_tree, &tgid);
  total_score = state->own_score;
  if (meta) {
    total_score += meta->inherited_score;
  }

  bpf_printk("[FILE PERMISSION TRIGGERED] score=%d path=%s\n", state->own_score, file->f_path.dentry->d_name.name);
  /* Policy decision */
  if (total_score >= policy->threshold) {
    /* TODO: log to a ringbuf */
    if (policy->mode == UAV_CGROUP_POLICY_BLOCK) {
      return -EPERM;  // BLOCK
    }
  }
  return 0;  // ALLOW
}

char LICENSE[] SEC("license") = "GPL";
