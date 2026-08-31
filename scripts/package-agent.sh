#!/bin/sh
set -eu

usage() {
    echo "Usage: $0 <config-header> <agent-binary>" >&2
    exit 1
}

[ "$#" -eq 2 ] || usage

config=$1
agent=$2

[ -f "$config" ] || {
    echo "Config not found: $config" >&2
    exit 1
}

[ -x "$agent" ] || {
    echo "Agent not found or not executable: $agent" >&2
    exit 1
}

initramfs=$(sed -n 's/^#define UAV_SANDBOX_INITRAMFS_PATH "\(.*\)"/\1/p' "$config")

[ -n "$initramfs" ] || {
    echo "UAV_SANDBOX_INITRAMFS_PATH not found in $config" >&2
    exit 1
}

work=$(mktemp -d)
output=$(mktemp "${initramfs}.tmp.XXXXXX")

cleanup() {
    rm -rf "$work"
    rm -f "$output"
}

trap cleanup EXIT

gzip -dc "$initramfs" | (cd "$work" && cpio -id --quiet)

install -Dm755 "$agent" "$work/sbin/uav-agent"

(
    cd "$work"
    find . -print0 |
        sort -z |
        cpio --null -o --quiet --format=newc --owner=0:0 |
        gzip -n > "$output"
)

mv "$output" "$initramfs"
