#ifndef UAV_SANDBOX_H
#define UAV_SANDBOX_H

#include <linux/limits.h>

enum uav_sandbox_backend {
  UAV_BACKEND_NAMESPACE = 0,
  UAV_BACKEND_KVM,
};

static const char *backend_names[] = {"NAMESPACE", "KVM"};

struct uav_sandbox_data {

};

struct uav_sandbox {
  /* Backend used to execute the sandbox */
  enum uav_sandbox_backend backend;

  /* Path to the root overlayfs */
  char path[PATH_MAX];

  /* Sandbox config data */
  union {
    unsigned char *stack;
    struct { } kvm;
  } data;
};

int uav_sandbox_create(struct uav_sandbox *s, enum uav_sandbox_backend type);
int uav_sandbox_run_program(const struct uav_sandbox *s, const char *program);
void uav_sandbox_destroy(struct uav_sandbox *s);

static const char sandbox_entrypoint_script[] =
    "#!/bin/sh\n"
    "set -e\n"
    "\n"
    "ln -sf /proc/self/fd /dev/fd\n"
    "ln -sf /proc/self/fd/0 /dev/stdin\n"
    "ln -sf /proc/self/fd/1 /dev/stdout\n"
    "ln -sf /proc/self/fd/2 /dev/stderr\n"
    "ln -sf pts/ptmx /dev/ptmx\n"
    "\n"
    "if [ \"$#\" -gt 0 ]; then\n"
    "    exec \"$@\"\n"
    "else\n"
    "    exec /bin/sh\n"
    "fi\n";

#endif //! UAV_SANDBOX_H
