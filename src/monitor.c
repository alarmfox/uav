#include <sys/stat.h>

#include "monitor.h"
#include "monitor_types.h"

#include "monitor.skel.h"

/* TODO: read this from file */
static const struct {
    const char *path;
    int read_weight;
    int write_weight;
    int chmod_weight;
    int unlink_weight;
} sensitive_files[] = {
    { "/etc/passwd",  20, 40, 60, 80 },
    { "/etc/shadow",  30, 50, 70, 90 },
    { "/etc/group",   15, 35, 55, 75 },
};
static size_t sfile_count = sizeof(sensitive_files) / sizeof(sensitive_files[0]);

static const struct {
  unsigned int cgroup;
  int policy;
  int threshold;
} cgroup_policies[] = {
  /* Fallback rule for all cgroup */
  {0, UAV_CGROUP_POLICY_LOG, 1000},
  /* Root cgroup */
  {1, UAV_CGROUP_POLICY_LOG, 1000},
};
static size_t policy_count = sizeof(cgroup_policies) / sizeof(cgroup_policies[0]);

static int add_sensitive_file(struct monitor_bpf *skel, const char *path, int read_weight, int write_weight, int chmod_weight, int unlink_weight);
static int add_cgroup_policy(struct monitor_bpf *skel, unsigned long cgroup, int policy, int threshold);

int uav_monitor_init(struct uav_monitor *m) {
  int ret;

  /* Open the program */
  m->prog = monitor_bpf__open();

  ret = monitor_bpf__load(m->prog);
  if(ret) {
    fprintf(stderr, "[MONITOR] cannot load bpf program\n");
    return 1;
  }

  /* Load cgroup policies */
  for(size_t i = 0; i < policy_count; ++i) {
    ret = add_cgroup_policy(m->prog,
        cgroup_policies[i].cgroup,
        cgroup_policies[i].policy,
        cgroup_policies[i].threshold
        );
    if(ret) return ret;
  }

  /* Load sensitve files */
  for (size_t i = 0; i < sfile_count; ++i) {
    ret = add_sensitive_file(
        m->prog,
        sensitive_files[i].path,
        sensitive_files[i].read_weight,
        sensitive_files[i].write_weight,
        sensitive_files[i].chmod_weight,
        sensitive_files[i].unlink_weight
        );
    if(ret) return ret;
  }

  return 0;
}

int uav_monitor_start(const struct uav_monitor *m) {
  if(!m) return 1;
  return monitor_bpf__attach(m->prog);
}

void uav_monitor_destroy(struct uav_monitor *m) {
  if(!m) return;

  /* Stop the ebpf program */
  monitor_bpf__detach(m->prog);
  monitor_bpf__destroy(m->prog);
}

/* Add an entry into the ebpf sensitive_inodes map */
static int add_sensitive_file(struct monitor_bpf *skel, const char *path, int read_weight, int write_weight, int chmod_weight, int unlink_weight) {
  struct stat st;
  int ret;

  ret = stat(path, &st);
  if (ret != 0) {
    fprintf(stderr, "Cannot stat %s: %m\n", path);
    return -1;
  }

  // NOW we create the actual map struct (from monitor_types.h)
  struct sensitive_file sens;

  // Initialize it
  memset(&sens, 0, sizeof(sens));

  sens.inode = st.st_ino;
  sens.read_weight = read_weight;
  sens.write_weight = write_weight;
  sens.chmod_weight = chmod_weight;
  sens.unlink_weight = unlink_weight;
  sens.flags = 0;

  // Use inode as key
  __u64 inode = st.st_ino;

  // Update the map with the REAL struct
  ret = bpf_map__update_elem(
      skel->maps.sensitive_inodes,
      &inode, sizeof(inode),
      &sens, sizeof(sens),
      BPF_ANY
      );

  if (ret != 0) {
    fprintf(stderr, "Failed to add file %s: %s\n", path, strerror(errno));
    return -1;
  }

  printf("Added: %s (inode=%llu)\n", path, inode);
  return 0;
}

static int add_cgroup_policy(struct monitor_bpf *skel, unsigned long cgroup, int policy, int threshold) {

  int ret;
  struct cgroup_policy pol;
  memset(&pol, 0, sizeof(struct cgroup_policy));

  pol.mode = policy;
  pol.threshold = threshold;

  __u64 key = cgroup;

  ret = bpf_map__update_elem(
      skel->maps.cgroup_policies,
      &key, sizeof(key),
      &pol, sizeof(pol),
      BPF_ANY
      );

  if(ret != 0) {
    fprintf(stderr, "Failed to add cgroup %lu policy: %s\n", cgroup, strerror(errno));
    return -1;
  }

  printf("Added policy for cgroup %lu: threshold=%d mode=%s\n", cgroup, threshold / 1000, policy == UAV_CGROUP_POLICY_BLOCK ? "BLOCK" : "LOG");
  return 0;
}
