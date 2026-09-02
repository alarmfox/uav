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

[ -n "$kernel" ] || {
    printf "UAV_SANDBOX_KERNEL_PATH not found in $config\n" >&2
    exit 1
}

work=$(mktemp -d "/tmp/uav-qemu-run.XXXXXX")
initramfs_in="$work/initramfs"
initramfs_out="$work/initramfs.cpio"

mkdir -p "$initramfs_in"

cleanup() {
    rm -rf "$work"
}

trap cleanup EXIT

# The exported stage includes Alpine's musl dynamic loader and the runtime
# libraries needed by the dynamically linked project executables.
DOCKER_BUILDKIT=1 docker build \
    --file Dockerfile.qemu \
    --target rootfs \
    --output "type=local,dest=$initramfs_in" \
    .

(
    cd "$initramfs_in"
    find . -print0 |
        sort -z |
        cpio --null -o --quiet --format=newc --owner=0:0 | gzip -n > "$initramfs_out"
)

qemu-system-x86_64 -m 128M \
    -smp 1 \
    -nographic \
    -kernel "$kernel" \
    -initrd "$initramfs_out"
