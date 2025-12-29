# UAV: Uncomplicated AntiVirus program for Linux

> [!WARNING]
> `uav` is an early development project.

A lightweight antivirus for Linux systems with rootless sandbox capabilities.


## Architecture

### Sandbox Design

The sandbox uses a hybrid architecture:

**Persistent Base Layer:**
- Read-only template shared across all executions (busybox)

**Ephemeral Instance Layer (per execution):**
- Temporary OverlayFS mount (base + copy-on-write upper layer)
- Unique network namespace with veth pair
- Dedicated cgroup with resource limits
- Cleaned up after program termination

**Isolation Mechanisms:**
- **Mount namespace:** Private filesystem view with pivot_root
- **Network namespace:** Isolated network stack, all traffic routed through host-side veth for inspection
- **PID namespace:** Process appears as PID 1 inside sandbox
- **UTS namespace:** Isolated hostname
- **Cgroup namespace:** Resource accounting isolation
- **Cgroups v2:** Memory, CPU, and PID limits enforced by kernel

**eBPF Integration:**
- LSM (Linux Security Module) hooks for mandatory access control
- Hooks on file operations, process creation, network access
- Configurable enforcement vs monitoring mode
- Per-cgroup policy attachment

### Network Architecture
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

All network traffic from sandbox is visible on host-side interface for inspection or filtering.

## Dependencies

**Runtime:**
- Linux kernel 5.7+ (for eBPF LSM support)
- Cgroups v2 (`CONFIG_CGROUP_BPF=y`)
- OverlayFS support
- Capabilities: `CAP_SYS_ADMIN`, `CAP_NET_ADMIN`, `CAP_SYS_CHROOT`

**Build:**
- libbpf (for eBPF program loading)
- OpenSSL libcrypto (for SHA-256 computation)
- libzip (for busybox archive extraction)
- libpcap (sandbox traffic capture)

## Building
```bash
make
```

This produces the `uav` binary.
