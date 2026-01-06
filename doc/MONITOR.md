# Monitor

The monitor attaches eBPF programs in specific points to track malicious behaviours by programs.
It works by applying cgroup policies mainting a suspicious score for every process in the system.

> [!WARNING]
> This part is very configuration specific. What I reported here _should_ work for common systems.

The Monitor heavily relies on Linux Security Module Hooks (requires kernel `>5.7`). On common
distributions such as Ubuntu, users wil need to allow the attach to eBPF. First they need to check

```sh
sudo cat /sys/kernel/security/lsm
```

If the output of the command contains `bpf`, there is nothing to do. Otherwise user will need to 
pass whatever is in the `/sys/kernel/security/lsm` adding `bpf` to the kernel cmdline. For example,
if `/sys/kernel/security/lsm` contains `lockdown,capability,yama`, they will need to pass `lockdown,capability,yama,bpf`.
On most systems this happens through grub adding something like this to `/etc/default/grub`:

```txt
GRUB_CMDLINE_LINUX_DEFAULT="loglevel=4 lsm=lockdown,capability,yama,bpf"
```
After modifiying the grub config, users will need to generate a new configuration and reboot their
system:

```sh
sudo grub-mkconfig -o /boot/grub/grub.cfg
```

## Mitre Att&cK
[TODO]

## OpenCTI
