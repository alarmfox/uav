# Sandbox

The sandbox is an isolated process with dedicated namespaces using [`clone(2)`](https://www.man7.org/linux/man-pages/man2/clone.2.html) and [`pivot_root(2)`](https://www.man7.org/linux/man-pages/man2/pivot_root.2.html).

Unshared namespaces are:
- **Network namespace:** Isolated network stack, all traffic routed through host-side veth for inspection
- **PID namespace:** Process appears as PID 1 inside sandbox
- **UTS namespace:** Isolated hostname
- **Cgroup namespace:** Resource accounting isolation

**Isolation Mechanisms:**
- **Mount namespace:** Private filesystem view with pivot_root
- **Cgroups v2:** Memory, CPU, and PID limits enforced by kernel

Default limitations are:
- CPU: 5% bandwith;
- Memory: 128Mb
- Pids: 20

The process uses the real user uid and gid to map the root user to achieve rootless.
Each sandbox execution uses temporary OverlayFS mount to create an ephemeral COW upper layer without
changing the base layer.

## Setting up a sandbox
The only thing needed to setup a sandbox is a rootfs filesystem. This can be a busybox instance
or a debian rootfs.
