#include "sandbox.h"

#include <errno.h>
#include <string.h>
#include <unistd.h>

/* Sandbox helpers */
int uav_sandbox_ns_create(struct uav_sandbox* s);
int uav_sandbox_ns_run(const struct uav_sandbox* s, const char* program,
                       const struct uav_agent_exec_params* params,
                       uint32_t duration_seconds);
int uav_sandbox_ns_destroy(struct uav_sandbox* s);
int uav_sandbox_kvm_create(struct uav_sandbox* s);
int uav_sandbox_kvm_run(const struct uav_sandbox* s, const char* program,
                        const struct uav_agent_exec_params* params,
                        uint32_t duration_seconds);
int uav_sandbox_kvm_destroy(struct uav_sandbox* s);

int uav_sandbox_create(struct uav_sandbox* s, enum uav_sandbox_backend type) {
  int ret;

  if (s == NULL) {
    errno = EINVAL;
    return -1;
  }

  /* Init sandbox */
  memset(s, 0, sizeof(struct uav_sandbox));
  s->backend = type;
  s->control_fd = -1;

  switch (s->backend) {
    case UAV_SANDBOX_BACKEND_CONTAINER:
      ret = uav_sandbox_ns_create(s);
      break;
    case UAV_SANDBOX_BACKEND_KVM:
      ret = uav_sandbox_kvm_create(s);
      break;
    default:
      errno = EINVAL;
      return -1;
  }

  return ret;
}

static int uav_sandbox_run_program_internal(
    const struct uav_sandbox* s, const char* program,
    const struct uav_agent_exec_params* params, uint32_t duration_seconds) {
  if (s == NULL || program == NULL || params == NULL) {
    errno = EINVAL;
    return -1;
  }

  switch (s->backend) {
    case UAV_SANDBOX_BACKEND_CONTAINER:
      return uav_sandbox_ns_run(s, program, params, duration_seconds);
    case UAV_SANDBOX_BACKEND_KVM:
      return uav_sandbox_kvm_run(s, program, params, duration_seconds);
  }

  errno = EINVAL;
  return -1;
}

int uav_sandbox_run_program(const struct uav_sandbox* s, const char* program,
                            const struct uav_agent_exec_params* params) {
  return uav_sandbox_run_program_internal(s, program, params, 0);
}

int uav_sandbox_run_program_with_deadline(
    const struct uav_sandbox* s, const char* program,
    const struct uav_agent_exec_params* params, uint32_t duration_seconds) {
  if (duration_seconds == 0) {
    errno = EINVAL;
    return -1;
  }

  return uav_sandbox_run_program_internal(s, program, params, duration_seconds);
}

int uav_sandbox_destroy(struct uav_sandbox* s) {
  int ret;
  int saved_errno;

  if (s == NULL) {
    errno = EINVAL;
    return -1;
  }

  switch (s->backend) {
    case UAV_SANDBOX_BACKEND_CONTAINER:
      ret = uav_sandbox_ns_destroy(s);
      break;
    case UAV_SANDBOX_BACKEND_KVM:
      ret = uav_sandbox_kvm_destroy(s);
      break;
    default:
      errno = EINVAL;
      return -1;
  }

  saved_errno = errno;
  if (s->control_fd >= 0) close(s->control_fd);
  s->control_fd = -1;
  if (ret < 0) errno = saved_errno;

  return ret;
}
