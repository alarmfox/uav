#!/bin/sh
set -eu

usage() {
    printf "Usage: %s <config-header>\n" "$0" >&2
    exit 1
}

[ "$#" -eq 1 ] || usage

[ -f "$1" ] || {
    printf "Config not found: %s\n" "$1" >&2
    exit 1
}

initramfs=$(sed -n 's/^#define UAV_SANDBOX_INITRAMFS_PATH "\(.*\)"/\1/p' "$1")

[ -n "$initramfs" ] || {
    printf "UAV_SANDBOX_INITRAMFS_PATH not found in %s\n" "$1" >&2
    exit 1
}

project=$(CDPATH= cd "$(dirname "$0")/.." && pwd)
work=$(mktemp -d "/tmp/uav-rootfs-package.XXXXXX")
output=

cleanup() {
    rm -rf "$work"
    if [ -n "$output" ]; then
        rm -f "$output"
    fi
}

trap cleanup 0

output=$(mktemp "$(dirname "$initramfs")/.$(basename "$initramfs").tmp.XXXXXX")

mkdir "$work/root"

DOCKER_BUILDKIT=1 docker build \
    --file "$project/Dockerfile.qemu" \
    --target rootfs \
    --output "type=local,dest=$work/root" \
    "$project"

(
    cd "$work/root"
    { find . -print0 || : > "$work/package.failed"; } |
        { sort -z || : > "$work/package.failed"; } |
        { cpio --null -o --quiet --format=newc --owner=0:0 ||
            : > "$work/package.failed"; } |
        gzip -n9
) > "$output"

[ ! -e "$work/package.failed" ] || exit 1

chmod 0644 "$output"

mv "$output" "$initramfs"
