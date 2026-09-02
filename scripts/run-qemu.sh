#!/bin/sh

set -eu

usage() {
    printf "Usage: %s <config-header>\n" "$0" >&2
    exit 1
}

[ "$#" -eq 1 ] || usage

config=$1

[ -f "$config" ] || {
    printf "Config not found: $config\n" >&2
    exit 1
}

kernel=$(sed -n 's/^#define UAV_SANDBOX_KERNEL_PATH "\(.*\)"/\1/p' "$config")
initramfs=$(sed -n 's/^#define UAV_SANDBOX_INITRAMFS_PATH "\(.*\)"/\1/p' "$config")

[ -n "$kernel" ] || {
    printf "UAV_SANDBOX_KERNEL_PATH not found in $config\n" >&2
    exit 1
}

[ -n "$initramfs" ] || {
    printf "UAV_SANDBOX_INITRAMFS_PATH not found in %s\n" "$config" >&2
    exit 1
}

[ -f "$kernel" ] || {
    printf "Kernel not found: %s\n" "$kernel" >&2
    exit 1
}

[ -f "$initramfs" ] || {
    printf "Initramfs not found: %s\n" "$initramfs" >&2
    exit 1
}

exec qemu-system-x86_64 -m 128M \
    -smp 1 \
    -nographic \
    -kernel "$kernel" \
    -initrd "$initramfs"
