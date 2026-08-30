#include <asm/bootparam.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/kvm.h>
#include <linux/kvm_para.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#include "config.h"
#include "sandbox.h"

/* Kernel Params  */
#define ZERO_PAGE_START      0x00010000
#define CMDLINE_START        0x00020000
#define KERNEL_LOAD_ADDR     0x00100000
#define INITRD_ALIGN         0x00001000
#define BOOT_STACK           0x00080000
#define GDT_START            0x00001000

static int kvm_setup_guest(int kvmfd, struct uav_sandbox *s);
static int kvm_load_images(const struct uav_sandbox *s);
static int kvm_setup_guest_vcpu(int kvmfd, struct uav_sandbox *s);

int uav_sandbox_kvm_create(struct uav_sandbox *s) {
  int ret = -1;
  int kvmfd = -1;

  s->data.kvm.guestfd = -1;
  s->data.kvm.vcpufd = -1;
  s->data.kvm.kernel_path = UAV_SANDBOX_KERNEL_PATH;
  s->data.kvm.initramfs_path = UAV_SANDBOX_INITRAMFS_PATH;
  s->data.kvm.guestmem_size = UAV_SANDBOX_KVM_GUEST_RAM;

  kvmfd = open("/dev/kvm", O_RDWR);
  if(kvmfd < 0) goto error;

  ret = kvm_setup_guest(kvmfd, s);
  if(ret <  0) goto error;

  ret = kvm_load_images(s);
  if (ret < 0) goto error;

  ret = kvm_setup_guest_vcpu(kvmfd, s);
  if(ret < 0) goto error;

  ret = 0;
error:
  if (kvmfd >= 0) close(kvmfd);
  if (ret != 0 && s->data.kvm.guestfd >= 0) {
    close(s->data.kvm.guestfd);
    s->data.kvm.guestfd = -1;
  }
  if (ret != 0 && s->data.kvm.vcpufd >= 0) {
    close(s->data.kvm.vcpufd);
    s->data.kvm.vcpufd = -1;
  }
  if (ret != 0 && s->data.kvm.guestmem != NULL) {
    munmap(s->data.kvm.guestmem, s->data.kvm.guestmem_size);
    s->data.kvm.guestmem = NULL;
  }

  return ret;
}

int uav_sandbox_kvm_run(const struct uav_sandbox *s, const char *program) {
  int kvmfd = -1;
  int ret = -1;
  int shouldexit = 0;

  kvmfd = open("/dev/kvm", O_RDWR);
  if(kvmfd < 0) goto error;

  /* Run the KVM vCPU */
  int run_size = ioctl(kvmfd, KVM_GET_VCPU_MMAP_SIZE, 0);
  struct kvm_run *run = mmap(0, run_size, PROT_READ | PROT_WRITE, MAP_SHARED, s->data.kvm.vcpufd, 0);

  while(!shouldexit) {
    /* Execute the VCPU */
    ret = ioctl(s->data.kvm.vcpufd, KVM_RUN, 0);

    if (ret < 0) {
      shouldexit = 1;
      fprintf(stderr, "[UAV] KVM run failed: %s\n", strerror(errno));
      continue;
    }
    switch (run->exit_reason) {
      case KVM_EXIT_SHUTDOWN:
        shouldexit = 1;
        break;

      case KVM_EXIT_INTERNAL_ERROR:
        fprintf(stderr, "======================");
        fprintf(stderr, "[UAV] KVM_EXIT_INTERNAL_ERROR\n");
        fprintf(stderr, "suberror = %u\n", run->internal.suberror);
        fprintf(stderr, "ndata = %u\n", run->internal.ndata);

        for (unsigned i = 0; i < run->internal.ndata; i++)
          fprintf(stderr, "data[%u] = 0x%llx\n", i, (unsigned long long)run->internal.data[i]);
        fprintf(stderr, "======================");
        shouldexit = 1;
        break;

      case KVM_EXIT_HLT:
        fprintf(stderr, "[UAV] KVM Guest halted\n");
        shouldexit = 1;
        break;
      case KVM_EXIT_IO:
        if (run->io.direction == KVM_EXIT_IO_OUT && run->io.port == 0xe9) {
          write(STDOUT_FILENO, (uint8_t *)run + run->io.data_offset, run->io.count);
        }
        break;

      default:
        fprintf(stderr, "[UAV] KVM unknown exit_reason: %d\n", run->exit_reason);
        shouldexit = 1;
        break;
    }

  }

  ret = 0;
error:
  if (kvmfd >= 0) close(kvmfd);
  return ret;
}

void uav_sandbox_kvm_destroy(struct uav_sandbox *s) {
  if (s->data.kvm.guestfd >= 0) close(s->data.kvm.guestfd);
  if (s->data.kvm.vcpufd >= 0) close(s->data.kvm.vcpufd);
  if (s->data.kvm.guestmem != NULL) munmap(s->data.kvm.guestmem, s->data.kvm.guestmem_size);
}

static int kvm_setup_guest(int kvmfd, struct uav_sandbox *s) {
  struct kvm_userspace_memory_region region;
  struct kvm_pit_config pit = {
    .flags = 0,
  };
  __u64 map_addr = 0xffffc000;
  int ret = -1;
  int saved_errno;

  s->data.kvm.guestfd = ioctl(kvmfd, KVM_CREATE_VM, 0);
  if (s->data.kvm.guestfd < 0) goto out;

  ret = ioctl(s->data.kvm.guestfd, KVM_SET_TSS_ADDR, 0xffffd000);
  if (ret < 0) goto out;

  ret = ioctl(s->data.kvm.guestfd, KVM_SET_IDENTITY_MAP_ADDR, &map_addr);
  if (ret < 0) goto out;

  /* Add IRQCHIP. */
  ret = ioctl(s->data.kvm.guestfd, KVM_CREATE_IRQCHIP, 0);
  if (ret < 0) goto out;

  /* Create PIT for timer interrupts. */
  ret = ioctl(s->data.kvm.guestfd, KVM_CREATE_PIT2, &pit);
  if (ret < 0) goto out;

  /* Map guest memory into userspace. */
  s->data.kvm.guestmem = mmap(
    NULL,
    s->data.kvm.guestmem_size,
    PROT_READ | PROT_WRITE,
    MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE,
    -1,
    0
  );

  if (s->data.kvm.guestmem == MAP_FAILED) {
    s->data.kvm.guestmem = NULL;
    goto out;
  }

  /* Configure and add memory region to the VM. */
  memset(&region, 0, sizeof(region));
  region.slot = 0;
  region.guest_phys_addr = 0;
  region.memory_size = s->data.kvm.guestmem_size;
  region.userspace_addr = (uintptr_t)s->data.kvm.guestmem;

  ret = ioctl(s->data.kvm.guestfd, KVM_SET_USER_MEMORY_REGION, &region);
  if (ret < 0) goto out;

  ret = 0;

out:
  saved_errno = errno;

  if (ret < 0) {
    if (s->data.kvm.guestmem != NULL) {
      munmap(s->data.kvm.guestmem, s->data.kvm.guestmem_size);
      s->data.kvm.guestmem = NULL;
    }

    if (s->data.kvm.guestfd >= 0) {
      close(s->data.kvm.guestfd);
      s->data.kvm.guestfd = -1;
    }
  }

  errno = saved_errno;
  return ret;
}

static int kvm_load_images(const struct uav_sandbox *s) {
  struct boot_params *boot;
  struct stat st;
  void *data = MAP_FAILED;
  size_t data_size = 0;
  unsigned setup_sects;
  size_t setup_size, kernel_size;
  uint32_t initrd_addr;
  int fd = -1;
  int ret = -1;
  int saved_errno;

  if (s->data.kvm.guestmem == NULL || s->data.kvm.kernel_path == NULL || s->data.kvm.initramfs_path == NULL) {
    errno = EINVAL;
    goto out;
  }

  boot = (struct boot_params *)((uint8_t *)s->data.kvm.guestmem + ZERO_PAGE_START);

  /* Load kernel image. */
  fd = open(s->data.kvm.kernel_path, O_RDONLY);
  if (fd < 0) goto out;

  if (fstat(fd, &st) < 0) goto out;

  if (st.st_size < (off_t)sizeof(struct boot_params)) {
    errno = EINVAL;
    goto out;
  }

  data_size = st.st_size;
  data = mmap(NULL, data_size, PROT_READ, MAP_PRIVATE, fd, 0);
  if (data == MAP_FAILED) goto out;

  close(fd);
  fd = -1;

  memset(boot, 0, sizeof(*boot));
  memcpy(boot, data, sizeof(*boot));

  /*
   * Linux 32-bit boot protocol. Boot directly into protected mode
   * without a bootloader.
   */
  if (boot->hdr.boot_flag != 0xaa55) {
    errno = EINVAL;
    goto out;
  }

  if (boot->hdr.header != 0x53726448) { /* "HdrS" */
    errno = EINVAL;
    goto out;
  }

  setup_sects = boot->hdr.setup_sects;
  if (setup_sects == 0) setup_sects = 4;

  setup_size = (setup_sects + 1) * 512;

  if (setup_size >= data_size) {
    errno = EINVAL;
    goto out;
  }

  kernel_size = data_size - setup_size;
  if (KERNEL_LOAD_ADDR + kernel_size > s->data.kvm.guestmem_size) {
    errno = EFBIG;
    goto out;
  }

  memcpy((uint8_t *)s->data.kvm.guestmem + KERNEL_LOAD_ADDR, (uint8_t *)data + setup_size, data_size - setup_size);

  munmap(data, data_size);
  data = MAP_FAILED;
  data_size = 0;

  strcpy((char *)s->data.kvm.guestmem + CMDLINE_START, "console=ttyS0 acpi=off pci=off");

  /* Boot parameters. */
  boot->hdr.type_of_loader = 0xff;
  boot->hdr.cmd_line_ptr = CMDLINE_START;
  boot->hdr.cmdline_size = 4096;
  boot->hdr.heap_end_ptr = 0xfe00;

  boot->e820_entries = 3;

  boot->e820_table[0].addr = 0x00000000;
  boot->e820_table[0].size = 0x0009fc00;
  boot->e820_table[0].type = 1;

  boot->e820_table[1].addr = 0x000f0000;
  boot->e820_table[1].size = 0x00010000;
  boot->e820_table[1].type = 2;

  boot->e820_table[2].addr = 0x00100000;
  boot->e820_table[2].size = s->data.kvm.guestmem_size - 0x00100000;
  boot->e820_table[2].type = 1;

  /* Load initrd. */
  fd = open(s->data.kvm.initramfs_path, O_RDONLY);
  if (fd < 0) goto out;

  if (fstat(fd, &st) < 0) goto out;

  if (st.st_size <= 0 || (uint64_t)st.st_size > s->data.kvm.guestmem_size) {
    errno = EFBIG;
    goto out;
  }

  data_size = st.st_size;
  data = mmap(NULL, data_size, PROT_READ, MAP_PRIVATE, fd, 0);
  if (data == MAP_FAILED) goto out;

  close(fd);
  fd = -1;

  initrd_addr = (s->data.kvm.guestmem_size - data_size) & ~(INITRD_ALIGN - 1);

  /*
   * Keep the initrd above the loaded kernel.
   */
  if (initrd_addr < KERNEL_LOAD_ADDR + (data_size - setup_size)) {
    errno = ENOMEM;
    goto out;
  }

  memcpy((uint8_t *)s->data.kvm.guestmem + initrd_addr, data, data_size);

  boot->hdr.ramdisk_image = initrd_addr;
  boot->hdr.ramdisk_size = data_size;

  ret = 0;

out:
  saved_errno = errno;

  if (data != MAP_FAILED) munmap(data, data_size);
  if (fd >= 0) close(fd);

  errno = saved_errno;
  return ret;

}

static int kvm_setup_guest_vcpu(int kvmfd, struct uav_sandbox *s) {
  struct {
    uint32_t nent;
    uint32_t padding;
    struct kvm_cpuid_entry2 entries[100];
  } kvm_cpuid;

  struct kvm_sregs sregs;
  struct kvm_regs regs;
  uint64_t *gdt;
  int ret = -1;
  int saved_errno;

  if (s->data.kvm.guestmem == NULL) {
    errno = EINVAL;
    goto out;
  }

  s->data.kvm.vcpufd = ioctl(s->data.kvm.guestfd, KVM_CREATE_VCPU, 0);
  if (s->data.kvm.vcpufd < 0) goto out;

  /* Setup CPUID. */
  memset(&kvm_cpuid, 0, sizeof(kvm_cpuid));
  kvm_cpuid.nent =
    sizeof(kvm_cpuid.entries) / sizeof(kvm_cpuid.entries[0]);

  ret = ioctl(kvmfd, KVM_GET_SUPPORTED_CPUID, &kvm_cpuid);
  if (ret < 0) goto out;

  for (unsigned int i = 0; i < kvm_cpuid.nent; i++) {
    struct kvm_cpuid_entry2 *entry = &kvm_cpuid.entries[i];

    if (entry->function == KVM_CPUID_SIGNATURE) {
      entry->eax = KVM_CPUID_FEATURES;
      entry->ebx = 0x4b4d564b; /* KVMK */
      entry->ecx = 0x564b4d56; /* VMKV */
      entry->edx = 0x0000004d; /* M */
    }
  }

  ret = ioctl(s->data.kvm.vcpufd, KVM_SET_CPUID2, &kvm_cpuid);
  if (ret < 0) goto out;

  /* Setup GDT. */
  gdt = (uint64_t *)((uint8_t *)s->data.kvm.guestmem + GDT_START);

  gdt[0] = 0x0000000000000000ULL; /* Null descriptor */
  gdt[1] = 0x00cf9a000000ffffULL; /* 32-bit kernel code */
  gdt[2] = 0x00cf92000000ffffULL; /* 32-bit kernel data */

  /* Setup vCPU special registers. */
  ret = ioctl(s->data.kvm.vcpufd, KVM_GET_SREGS, &sregs);
  if (ret < 0) goto out;

  sregs.gdt.base = GDT_START;
  sregs.gdt.limit = 3 * 8 - 1;

  /* Code segment (selector 0x08). */
  sregs.cs.base = 0;
  sregs.cs.limit = 0xffffffff;
  sregs.cs.selector = 0x08;
  sregs.cs.type = 0x0b;
  sregs.cs.present = 1;
  sregs.cs.dpl = 0;
  sregs.cs.db = 1;
  sregs.cs.s = 1;
  sregs.cs.l = 0;
  sregs.cs.g = 1;
  sregs.cs.avl = 0;

  /* Data segments (selector 0x10). */
  sregs.ds.base = 0;
  sregs.ds.limit = 0xffffffff;
  sregs.ds.selector = 0x10;
  sregs.ds.type = 0x03;
  sregs.ds.present = 1;
  sregs.ds.dpl = 0;
  sregs.ds.db = 1;
  sregs.ds.s = 1;
  sregs.ds.l = 0;
  sregs.ds.g = 1;
  sregs.ds.avl = 0;

  sregs.es = sregs.ds;
  sregs.fs = sregs.ds;
  sregs.gs = sregs.ds;
  sregs.ss = sregs.ds;

  sregs.cr0 |= 0x11;
  sregs.cr4 = 0;
  sregs.efer = 0;

  ret = ioctl(s->data.kvm.vcpufd, KVM_SET_SREGS, &sregs);
  if (ret < 0) goto out;

  /* Setup vCPU regular registers. */
  memset(&regs, 0, sizeof(regs));

  regs.rip = KERNEL_LOAD_ADDR;
  regs.rsi = ZERO_PAGE_START;
  regs.rsp = BOOT_STACK;
  regs.rbp = BOOT_STACK;
  regs.rflags = 0x2;

  ret = ioctl(s->data.kvm.vcpufd, KVM_SET_REGS, &regs);
  if (ret < 0) goto out;

  ret = 0;

out:
  saved_errno = errno;

  if (ret < 0 && s->data.kvm.vcpufd >= 0) {

  close(s->data.kvm.vcpufd);
  s->data.kvm.vcpufd = -1;
  }

  errno = saved_errno;
  return ret;
}
