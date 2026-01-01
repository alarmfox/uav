# UAV: Uncomplicated AntiVirus program for Linux

> [!WARNING]
> `uav` is an early development project.

A lightweight antivirus for Linux systems with rootless sandbox capabilities.

## Scope
The idea is to create a simple and reliable malware detection program suitable for normal users and 
to give some advanced tool to do some malware analysis to experienced users.

## Architecture

`uav` is a single executable and has mainly 3 modes:
- protection mode: always on -> inspect every program the user executes
- sandbox mode: support rootless isolated execution for malware analysis or sanity check of untrusted 
programs
- scan mode: scan a file providing a report with information like signature

More information in [docs](./docs/).

**eBPF Integration:**
- LSM (Linux Security Module) hooks for mandatory access control
- Hooks on file operations, process creation, network access
- Per-cgroup policy attachment

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
```sh
make
```

This produces the `uav` binary.

### Run a sandbox
To run a program in a sandbox:
```sh
sudo ./uav sandbox -r <path-to-rootfs> <suspicious-file>
```

If the rootfs ends with `.zip`, `uav` will attempt to extract it. If `suspicious-file` is not
specified an interactive shell will be executed instead.

## Running tests

> [!NOTE]
> Some tests (the one regarding the sandbox) need to be executed with root privileges (i.e sudo).

User can run test with:
```sh
make test
```

If they have Valgrind the test can be run with:
```sh
make valgrind
```
