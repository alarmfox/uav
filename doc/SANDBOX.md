# Sandbox

The sandbox is an isolated process with dedicated namespaces using [`clone(2)`](https://www.man7.org/linux/man-pages/man2/clone.2.html) 
and [`pivot_root(2)`](https://www.man7.org/linux/man-pages/man2/pivot_root.2.html). Unshared namespaces are:

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

The process uses the real user uid and gid to map the root user to achieve rootless. By default, the sandbox is 
created upon a minimal busybox environment, but you can make the "rootfs" be whatever you want.

Each sandbox execution uses temporary OverlayFS mount to create an ephemeral COW upper layer without 
changing the base layer.

## Setting up a sandbox
The only thing needed to setup a sandbox is a rootfs filesystem. This can be a busybox instance
or a debian rootfs.

[TODO]

## Network Architecture

All network traffic from sandbis visible on host-side interface for inspection or filtering. This
is achieved by creating veth pair and moving one-end into sandbox through [Netlink (7)](https://www.man7.org/linux/man-pages/man7/netlink.7.html).

```
Host Network Namespace
  |
  +-- veth (host-side): 10.10.10.1/30
      |
      | (virtual ethernet pair)
      |
Sandbox Network Namespace
  |
  +-- veth (sandbox-side): 10.10.10.2/30
      |
      +-- default route via 10.10.10.1
```

All traffic routed from the veth pair will be captured in a pcap file and made available to the user.

### Obtaining internet access

> [!INFO]
> I am currently working an eBPF NAT system which allows to provide high performance Traffic Control 
without any extra action.

Users can give internet access to the sandbox. This can happen in a few ways:
- creating nat with iptables
- creating a bridge connecting the host-side veth and the main IP address

