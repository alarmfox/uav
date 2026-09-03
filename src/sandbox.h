#ifndef UAV_SANDBOX_H
#define UAV_SANDBOX_H

#include <linux/limits.h>
#include <stddef.h>
#include <stdint.h>
#include <unistd.h>

enum uav_sandbox_backend {
  UAV_SANDBOX_BACKEND_CONTAINER = 0,
  UAV_SANDBOX_BACKEND_KVM,
};

struct uav_agent_exec_params;

struct uav_sandbox {
  /* Backend used to execute the sandbox */
  enum uav_sandbox_backend backend;

  /* Control file descriptor */
  int control_fd;

  /* Sandbox data */
  union {
    struct {
      /* Pid of the container */
      pid_t child;
      /* Base of the stack */
      unsigned char* stack;
      /* Path to the sandbox root */
      char path[PATH_MAX];
    } container;
    struct {
      /* Guest file descriptor */
      int guestfd;
      /* vCPU file descriptor */
      int vcpufd;
      /* Pointer to guest memory */
      void* guestmem;
      /* Guest memory size */
      size_t guestmem_size;
      /* Path to kernel */
      const char* kernel_path;
      /* Path to initramfs */
      const char* initramfs_path;
    } kvm;
  } data;
};

int uav_sandbox_create(struct uav_sandbox* s, enum uav_sandbox_backend type);
int uav_sandbox_run_program(const struct uav_sandbox* s, const char* program,
                            const struct uav_agent_exec_params* params);
int uav_sandbox_run_program_with_deadline(
    const struct uav_sandbox* s, const char* program,
    const struct uav_agent_exec_params* params, uint32_t duration_seconds);
int uav_sandbox_destroy(struct uav_sandbox* s);

#endif  //! UAV_SANDBOX_H
