#ifndef __UAV_SANDBOX_H
#define __UAV_SANDBOX_H

#include <arpa/inet.h>
#include <net/if.h>
#include <limits.h>

#include "cgroup.h"

static const char BUSYBOX_ZIP [] = "data/uav_sandbox_busybox.zip";
static const char SANDBOX_ENTRYPOINT[] = "data/uav_sandbox_entrypoint.sh";

/* Default limits */
static const struct uav_cgroup_limits DEFAULT_LIMITS = {
  /* 128M */
  .memory_max = 1024 * 1024 * 128,
  /* 5% cpu */
  .cpu_max = 5000,
  /* 20 forks */
  .pids_max = 20,
  /* 1MB stack */
  .stack_size = 1024 * 1024,
  /* 16MB tmpfs */
  .tmpfs_size = 1024 * 1024 * 16,
};

struct uav_sandbox_config {
  /* Actual path where runtime data is stored. Overlayfs */
  char overlay_path[PATH_MAX];
  /* Name of the veth used by the host */
  char hostifname[IFNAMSIZ];
  /* Name of the veth used by the sandbox */
  char sandboxifname[IFNAMSIZ];
  /* IPv4 address of the host-side */
  char hostip[64];
  /* IPv4 address of the sandbox-side */
  char sandboxip[64];
  /* Network prefix */
  unsigned int prefix;
};

/* Sandbox instance data. */
struct uav_sandbox {
  /* Identifier */
  char id[64];
  /* Path of the root filesystem tree */
  char root[PATH_MAX];
  /* Actual path where runtime data is stored. Overlayfs */
  char overlay_path[PATH_MAX];
  /* Name of the veth used by the host */
  char hostifname[IFNAMSIZ];
  /* Name of the veth used by the sandbox */
  char sandboxifname[IFNAMSIZ];
  /* IPv4 address of the host-side */
  struct in_addr hostip;
  /* IPv4 address of the sandbox-side */
  struct in_addr sandboxip;
  /* Prefix for the network */
  unsigned int prefix;
  /* Limits to be applied to the sandbox */
  struct uav_cgroup_limits limits;
  /* Reference to eBPF program */
  struct sandbox_bpf *skel;
  /* Pointer to stack bottom: stack + limits.stack_size = stack_top */
  unsigned char *stack;
  /* Signal to extract */
  int initialized;
};

int uav_sandbox_base_bootstrap(struct uav_sandbox *si, const char *sandbox_dir);
int uav_sandbox_configure(struct uav_sandbox *s, const struct uav_cgroup_limits *limits, const struct uav_sandbox_config *config);
int uav_sandbox_run_program(struct uav_sandbox *s, const char *program);
void uav_sandbox_destroy(struct uav_sandbox *s);

/* Sandbox entrypoint script. */
static const char entrypoint[] =
  "#!/bin/sh\n"
  "mkdir -p /home /root \n"
  "echo 'root:x:0:0:root:/root:/bin/sh' > /etc/passwd\n"
  "echo 'nameserver 1.1.1.1' > /etc/resolv.conf\n"
  "export PS1='(\\u@\\h)>' \n"
  "exec $@";

#endif // !__UAV_SANDBOX_H
