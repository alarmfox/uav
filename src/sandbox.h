#ifndef UAV_SANDBOX_H
#define UAV_SANDBOX_H

#include <linux/limits.h>

struct uav_sandbox {
  /* Path to the root overlayfs */
  char path[PATH_MAX];

  /* Top of the stack */
  unsigned char *stack;
};

int uav_sandbox_create(struct uav_sandbox *s);
int uav_sandbox_run_program(const struct uav_sandbox *s, const char *program);
void uav_sandbox_destroy(struct uav_sandbox *s);

static const char sandbox_entrypoint_script[] =
    "#!/bin/sh\n"
    "set -e\n"
    "\n"
    "/bin/busybox --install -s\n"
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
