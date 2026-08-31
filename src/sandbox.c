#include "sandbox.h"

#include <errno.h>
#include <string.h>
#include <unistd.h>

#include "transport.h"

/* Sandbox helpers */
int uav_sandbox_ns_create(struct uav_sandbox* s);
int uav_sandbox_ns_run(const struct uav_sandbox* s, const char* program);
int uav_sandbox_ns_destroy(struct uav_sandbox* s);
int uav_sandbox_kvm_create(struct uav_sandbox* s);
int uav_sandbox_kvm_run(const struct uav_sandbox* s, const char* program);
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

int uav_sandbox_run_program(const struct uav_sandbox* s, const char* program) {
  if (s == NULL || program == NULL) {
    errno = EINVAL;
    return -1;
  }

  switch (s->backend) {
    case UAV_SANDBOX_BACKEND_CONTAINER:
      return uav_sandbox_ns_run(s, program);
    case UAV_SANDBOX_BACKEND_KVM:
      return uav_sandbox_kvm_run(s, program);
  }

  errno = EINVAL;
  return -1;
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
  uav_transport_destroy(&s->trans);
  if (ret < 0) errno = saved_errno;

  return ret;
}
