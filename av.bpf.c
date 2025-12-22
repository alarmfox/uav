#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

const volatile __u64 target_cgroup_id;

SEC("tp/syscalls/sys_enter_execve")
int handle_execve(void *ctx) {

  __u64 cgroup_id = bpf_get_current_cgroup_id();

  /* Filter out non target processes */
  if (cgroup_id != target_cgroup_id) {
    return 0;
  }

  bpf_printk("Hello BPF; cgroup id %lu\n", cgroup_id);

  return 0;
}

char LICENSE[] SEC("license") = "GPL";
