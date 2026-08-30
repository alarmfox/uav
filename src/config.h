#ifndef UAV_CONFIG_H
#define UAV_CONFIG_H

#include <assert.h>
#include <limits.h>
#include <linux/limits.h>

#define UAV_SANDBOX_DIR "/tmp"

_Static_assert(sizeof(UAV_SANDBOX_DIR) + sizeof("/uav_sandbox_XXXXXX") < PATH_MAX, "UAV_SANDBOX_DIR is too big");

#define UAV_SANDBOX_INITRAMFS_PATH "/tmp/initramfs.cpio.gz"

#define UAV_SANDBOX_KERNEL_PATH "/tmp/bzImage"

#define UAV_SANDBOX_NS_STACK_SIZE (1024 * 1024)
_Static_assert(UAV_SANDBOX_NS_STACK_SIZE % 16 == 0, "sandbox stack size must preserve 16-byte alignment");

#define UAV_SANDBOX_KVM_GUEST_RAM (1024 * 1024 * 32)
_Static_assert(UAV_SANDBOX_NS_STACK_SIZE % 16 == 0, "sandbox guest memory size must preserve 16-byte alignment");

#endif //!UAV_CONFIG_H
