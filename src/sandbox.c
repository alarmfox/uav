#include "sandbox.h"

#include <errno.h>
#include <string.h>
#include <unistd.h>

/* Sandbox helpers */
int uav_sandbox_ns_create(struct uav_sandbox* s);
int uav_sandbox_ns_run(const struct uav_sandbox* s, const char* program);
int uav_sandbox_ns_destroy(struct uav_sandbox* s);
int uav_sandbox_kvm_create(struct uav_sandbox* s);
int uav_sandbox_kvm_run(const struct uav_sandbox* s, const char* program);
int uav_sandbox_kvm_destroy(struct uav_sandbox* s);

int uav_sandbox_create(struct uav_sandbox* s, enum uav_sandbox_backend type) {
  if (s == NULL) {
    errno = EINVAL;
    return -1;
  }

  /* Init sandbox */
  memset(s, 0, sizeof(struct uav_sandbox));
  s->data.ns.control_fd = -1;
  s->data.ns.child = -1;
  s->backend = type;

  switch (s->backend) {
    case UAV_SANDBOX_BACKEND_NS:
      return uav_sandbox_ns_create(s);
    case UAV_SANDBOX_BACKEND_KVM:
      return uav_sandbox_kvm_create(s);
  }

  errno = EINVAL;
  return -1;
}

int uav_sandbox_run_program(const struct uav_sandbox* s, const char* program) {
  if (s == NULL || program == NULL) {
    errno = EINVAL;
    return -1;
  }

  switch (s->backend) {
    case UAV_SANDBOX_BACKEND_NS:
      return uav_sandbox_ns_run(s, program);
    case UAV_SANDBOX_BACKEND_KVM:
      return uav_sandbox_kvm_run(s, program);
  }

  errno = EINVAL;
  return -1;
}

int uav_sandbox_destroy(struct uav_sandbox* s) {
  if (s == NULL) {
    errno = EINVAL;
    return -1;
  }

  switch (s->backend) {
    case UAV_SANDBOX_BACKEND_NS:
      return uav_sandbox_ns_destroy(s);
    case UAV_SANDBOX_BACKEND_KVM:
      return uav_sandbox_kvm_destroy(s);
  }

  return -1;
}
