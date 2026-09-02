#ifndef UAV_CONFIG_H
#define UAV_CONFIG_H

#include <assert.h>
#include <limits.h>
#include <linux/limits.h>

#define UAV_SANDBOX_DIR "/tmp"

_Static_assert(sizeof(UAV_SANDBOX_DIR) + sizeof("/uav_sandbox_XXXXXX") <
                   PATH_MAX,
               "UAV_SANDBOX_DIR is too big");

#define UAV_SANDBOX_INITRAMFS_PATH "initramfs.cpio.gz"

#define UAV_SANDBOX_KERNEL_PATH "linux-7.1-minimal"

#define UAV_SANDBOX_CONTAINER_STACK_SIZE (1024 * 1024)
_Static_assert(UAV_SANDBOX_CONTAINER_STACK_SIZE % 16 == 0,
               "sandbox stack size must preserve 16-byte alignment");

#define UAV_SANDBOX_KVM_GUEST_RAM (1024 * 1024 * 32)
_Static_assert(UAV_SANDBOX_KVM_GUEST_RAM % 16 == 0,
               "sandbox guest memory size must preserve 16-byte alignment");

#define UAV_UAVD_RUNTIME_DIR "/tmp/uavd"
#define UAV_UAVD_CONTROL_PATH UAV_UAVD_RUNTIME_DIR "/control.sock"
#define UAV_UAVD_ROOT_CGROUP_NAME "uav"

#endif  //! UAV_CONFIG_H
