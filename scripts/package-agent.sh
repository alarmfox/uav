#!/bin/sh
set -eu

usage() {
    printf "Usage: $0 <config-header> <agent-binary>\n" >&2
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
    printf "Agent not found or not executable: $agent\n" >&2
    exit 1
}

initramfs=$(sed -n 's/^#define UAV_SANDBOX_INITRAMFS_PATH "\(.*\)"/\1/p' "$config")

[ -n "$initramfs" ] || {
    printf "UAV_SANDBOX_INITRAMFS_PATH not found in $config\n" >&2
    exit 1
}

[ -f "$initramfs" ] || {
    printf "Initramfs not found: $initramfs\n" >&2
    exit 1
}

work=$(mktemp -d)
root="$work/root"
input="$work/input.cpio"
initramfs_dir=$(dirname "$initramfs")
initramfs_name=$(basename "$initramfs")
output=$(mktemp "$initramfs_dir/.${initramfs_name}.tmp.XXXXXX")

cleanup() {
    rm -rf "$work"
    rm -f "$output"
}

trap cleanup EXIT

mkdir "$root"
gzip -dc "$initramfs" > "$input"
(cd "$root" && cpio -id --quiet < "$input")

install -Dm755 "$agent" "$root/sbin/uav-agent"

(
    cd "$root"
    find . -print0 |
        sort -z |
        cpio --null -o --quiet --format=newc --owner=0:0 |
        gzip -n9
    ) > "$output"

chmod --reference="$initramfs" "$output"

mv "$output" "$initramfs"
