# UAV: Uncomplicated AntiVirus for Linux

> [!WARNING]
> `uav` is an early development project.

A lightweight antivirus for Linux systems.

## Scope
The idea is to create a simple and reliable malware detection program suitable for normal users and
to give some advanced tool to do some malware analysis to experienced users.

The goal is to have a program that has:

- protection-mode: look for specific patterns;
- scan-mode: scan files or directories for signature based analysis;
- sandbox-mode: dynamic analysis in a sandbox;

## Architecture

- `uav` is the unprivileged command-line client that creates and runs the
  sandbox.
- `uavd` is the privileged host component. It places sandbox processes in
  cgroups and manages the eBPF programs used for real-time detection.
- `uav-agent` runs inside container and KVM sandboxes and executes commands
  received through the agent protocol.

## Dependencies

**Runtime:**
- Linux kernel 5.7+ (for eBPF LSM support)
- Cgroups v2 (`CONFIG_CGROUP_BPF=y`)
- OverlayFS support
- Capabilities: `CAP_SYS_ADMIN`, `CAP_NET_ADMIN`, `CAP_SYS_CHROOT`

## Building
```sh
make
```
