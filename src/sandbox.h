#ifndef UAV_SANDBOX_H
#define UAV_SANDBOX_H

#include <linux/limits.h>
#include <stddef.h>

enum uav_sandbox_backend {
  UAV_BACKEND_NS = 0,
  UAV_BACKEND_KVM,
};

struct uav_sandbox {
  /* Backend used to execute the sandbox */
  enum uav_sandbox_backend backend;

  /* Path to the root overlayfs */
  char path[PATH_MAX];

  /* Sandbox config data */
  union {
    unsigned char *stack;
    struct {
      int guestfd;
      int vcpufd;
      void *guestmem;
      size_t guestmem_size;
      const char *kernel_path;
      const char *initramfs_path;
    } kvm;
  } data;
};

int uav_sandbox_create(struct uav_sandbox *s, enum uav_sandbox_backend type);
int uav_sandbox_run_program(const struct uav_sandbox *s, const char *program);
void uav_sandbox_destroy(struct uav_sandbox *s);

static const char *subdirs[] = { "/base","/merged", "/upper", "/work"};

#endif //! UAV_SANDBOX_H
