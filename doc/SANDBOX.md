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
  +-- veth1 (host-side): 10.10.10.1/30
      |
      | (virtual ethernet pair)
      |
Sandbox Network Namespace
  |
  +-- veth2 (sandbox-side): 10.10.10.2/30
      |
      +-- default route via 10.10.10.1
```

All traffic routed from the veth pair will be captured in a pcap file and made available to the user.

### Internet Access

> [!WARNING]
By default the sandbox has not access to the Internet.

> [!INFO]
> I am currently working an eBPF NAT system which allows to provide high performance Traffic Control 
without any extra action.

A simple way to get internet access is by NAT using iptables. This is not the most elegant way but
it is the simplest way. Assuming network setup above, users will have to issue the following commands:

```sh
$ iptables -t nat -A POSTROUTING -s 10.10.10.0/30 -o <output-interface> -j MASQUERADE
```

If users have docker and/or libvirt they will likely be blocked by their forwarding rules. Users can
issue these command to ensure that the traffic is formwarded:

```sh
$ iptables -I FORWARD 1 -i veth1 -o <output-interface>  -j ACCEPT
$ iptables -I FORWARD 2 -i <output-interface> -o veth1 -m state --state RELATED,ESTABLISHED -j ACCEPT
```
