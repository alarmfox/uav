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

#endif //! UAV_SANDBOX_H
