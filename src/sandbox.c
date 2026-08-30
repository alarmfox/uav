#include <errno.h>
#include <string.h>
#include <unistd.h>

#include "sandbox.h"

/* Sandbox helpers */
int uav_sandbox_ns_create(struct uav_sandbox * s);
int uav_sandbox_ns_run(const struct uav_sandbox * s, const char *program);
void uav_sandbox_ns_destroy(struct uav_sandbox * s);
int uav_sandbox_kvm_create(struct uav_sandbox * s);
int uav_sandbox_kvm_run(const struct uav_sandbox * s, const char *program);
void uav_sandbox_kvm_destroy(struct uav_sandbox * s);

int uav_sandbox_create(struct uav_sandbox *s, enum uav_sandbox_backend type) {
  if (s == NULL) {
    errno = EINVAL;
    return -1;
  }

  memset(s, 0, sizeof(struct uav_sandbox));
  s->backend = type;
  switch (s->backend) {
    case UAV_SANDBOX_BACKEND_NS:
      return uav_sandbox_ns_create(s);
    case UAV_SANDBOX_BACKEND_KVM:
      return uav_sandbox_kvm_create(s);
  }

  return -1;
}

int uav_sandbox_run_program(const struct uav_sandbox *s, const char *program) {
  if(s == NULL) {
    errno = EINVAL;
    return -1;
  }

  switch (s->backend) {
    case UAV_SANDBOX_BACKEND_NS:
      return uav_sandbox_ns_run(s, program);
    case UAV_SANDBOX_BACKEND_KVM:
      return uav_sandbox_kvm_run(s, program);
  }

  return -1;
}

void uav_sandbox_destroy(struct uav_sandbox *s) {
  if(s == NULL) return;

  switch (s->backend) {
    case UAV_SANDBOX_BACKEND_NS:
      uav_sandbox_ns_destroy(s);
      break;
    case UAV_SANDBOX_BACKEND_KVM:
      uav_sandbox_kvm_destroy(s);
      break;
  }

}
