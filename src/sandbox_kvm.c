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
#define ZERO_PAGE_START 0x00010000
#define CMDLINE_START 0x00020000
#define KERNEL_LOAD_ADDR 0x00100000
#define INITRD_ALIGN 0x00001000
#define BOOT_STACK 0x00080000
#define GDT_START 0x00001000

static int kvm_setup_guest(int kvmfd, struct uav_sandbox* s);
static int kvm_load_images(const struct uav_sandbox* s);
static int kvm_setup_guest_vcpu(int kvmfd, struct uav_sandbox* s);

int uav_sandbox_kvm_create(struct uav_sandbox* s) {
  int ret = -1;
  int kvmfd = -1;

  s->data.kvm.guestfd = -1;
  s->data.kvm.vcpufd = -1;
  s->data.kvm.kernel_path = UAV_SANDBOX_KERNEL_PATH;
  s->data.kvm.initramfs_path = UAV_SANDBOX_INITRAMFS_PATH;
  s->data.kvm.guestmem_size = UAV_SANDBOX_KVM_GUEST_RAM;

  kvmfd = open("/dev/kvm", O_RDWR);
  if (kvmfd < 0) goto error;

  ret = kvm_setup_guest(kvmfd, s);
  if (ret < 0) goto error;

  ret = kvm_load_images(s);
  if (ret < 0) goto error;

  ret = kvm_setup_guest_vcpu(kvmfd, s);
  if (ret < 0) goto error;

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

int uav_sandbox_kvm_run(const struct uav_sandbox* s, const char* program) {
  (void)program;
  int kvmfd = -1;
  int ret = -1;
  int shouldexit = 0;
  int mmap_size;
  int m;
  size_t run_size;
  struct kvm_run* run = NULL;

  kvmfd = open("/dev/kvm", O_RDWR);
  if (kvmfd < 0) goto out;

  /* Run the KVM vCPU */
  mmap_size = ioctl(kvmfd, KVM_GET_VCPU_MMAP_SIZE, 0);

  if (mmap_size < 0) goto out;
  if ((size_t)mmap_size < sizeof(struct kvm_run)) {
    errno = EPROTO;
    goto out;
  }

  run_size = (size_t)mmap_size;
  run = mmap(0, run_size, PROT_READ | PROT_WRITE, MAP_SHARED,
             s->data.kvm.vcpufd, 0);

  if (run == MAP_FAILED) {
    run = NULL;
    goto out;
  }

  while (!shouldexit) {
    /* Execute the VCPU */
    ret = ioctl(s->data.kvm.vcpufd, KVM_RUN, 0);

    if (ret < 0) {
      shouldexit = 1;
      fprintf(stderr, "[UAV] KVM run failed: %s\n", strerror(errno));
      continue;
    }
    switch (run->exit_reason) {
      case KVM_EXIT_HLT:
      case KVM_EXIT_SHUTDOWN:
        shouldexit = 1;
        ret = 0;
        goto out;

      case KVM_EXIT_INTERNAL_ERROR:
        fprintf(stderr, "======================");
        fprintf(stderr, "[UAV] KVM_EXIT_INTERNAL_ERROR\n");
        fprintf(stderr, "suberror = %u\n", run->internal.suberror);
        fprintf(stderr, "ndata = %u\n", run->internal.ndata);

        for (unsigned i = 0; i < run->internal.ndata; i++)
          fprintf(stderr, "data[%u] = 0x%llx\n", i,
                  (unsigned long long)run->internal.data[i]);
        fprintf(stderr, "======================");
        shouldexit = 1;
        ret = -1;
        errno = EIO;
        break;

      case KVM_EXIT_IO: {
        uint8_t* data = (uint8_t*)run + run->io.data_offset;
        size_t len = run->io.size * run->io.count;

        if (run->io.direction == KVM_EXIT_IO_IN) {
          for (unsigned i = 0; i < run->io.count; i++) {
            uint8_t* value = data + i * run->io.size;

            switch (run->io.port) {
              case 0x3fd:
                value[0] = 0x60;
                break;

              default:
                memset(value, 0, run->io.size);
                break;
            }
          }
        } else {
          switch (run->io.port) {
            case 0x3f8:
              m = write(STDOUT_FILENO, data, len);
              (void)m;
              break;
          }
        }
        break;
      }
      case KVM_EXIT_MMIO:
        fprintf(stderr, "[UAV] MMIO: addr=0x%llx len=%u write=%u data=",
                (unsigned long long)run->mmio.phys_addr, run->mmio.len,
                run->mmio.is_write);

        for (unsigned i = 0; i < run->mmio.len; i++)
          fprintf(stderr, "%02x ", run->mmio.data[i]);

        fprintf(stderr, "\n");

        /*
         * For an MMIO read, userspace must provide the value
         * before calling KVM_RUN again.
         */
        if (!run->mmio.is_write) memset(run->mmio.data, 0, run->mmio.len);

        break;
      default:
        fprintf(stderr, "[UAV] KVM unknown exit_reason: %d\n",
                run->exit_reason);
        shouldexit = 1;
        ret = -1;
        errno = EIO;
        break;
    }
  }

out:
  if (kvmfd >= 0) close(kvmfd);
  if (run != NULL) munmap(run, run_size);
  return ret;
}

int uav_sandbox_kvm_destroy(struct uav_sandbox* s) {
  if (s == NULL) {
    errno = EINVAL;
    return -1;
  }

  if (s->data.kvm.guestfd >= 0) close(s->data.kvm.guestfd);
  if (s->data.kvm.vcpufd >= 0) close(s->data.kvm.vcpufd);
  if (s->data.kvm.guestmem != NULL)
    munmap(s->data.kvm.guestmem, s->data.kvm.guestmem_size);

  return 0;
}

static int kvm_setup_guest(int kvmfd, struct uav_sandbox* s) {
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
  s->data.kvm.guestmem =
      mmap(NULL, s->data.kvm.guestmem_size, PROT_READ | PROT_WRITE,
           MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0);

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

static int kvm_load_images(const struct uav_sandbox* s) {
  struct boot_params* boot;
  struct stat st;
  void* data = MAP_FAILED;
  size_t data_size = 0;
  size_t kernel_size;
  unsigned setup_sects;
  size_t setup_size;
  uint64_t kernel_end;
  uint64_t initrd_top;
  uint64_t initrd_addr64;
  uint32_t initrd_addr;
  int fd = -1;
  int ret = -1;
  int saved_errno;

  if (s->data.kvm.guestmem == NULL || s->data.kvm.kernel_path == NULL ||
      s->data.kvm.initramfs_path == NULL) {
    errno = EINVAL;
    goto out;
  }

  boot =
      (struct boot_params*)((uint8_t*)s->data.kvm.guestmem + ZERO_PAGE_START);

  /* Load kernel image. */
  fd = open(s->data.kvm.kernel_path, O_RDONLY);
  if (fd < 0) goto out;

  if (fstat(fd, &st) < 0) goto out;

  if (st.st_size < 0x202) {
    errno = EINVAL;
    goto out;
  }

  data_size = st.st_size;
  data = mmap(NULL, data_size, PROT_READ, MAP_PRIVATE, fd, 0);
  if (data == MAP_FAILED) goto out;

  close(fd);
  fd = -1;

  /*
   * boot_params must be zero initialized.
   * Only copy the setup header from the bzImage.
   */
  memset(boot, 0, sizeof(*boot));

  if (0x1f1 + sizeof(boot->hdr) > data_size) {
    errno = EINVAL;
    goto out;
  }

  memcpy(&boot->hdr, (uint8_t*)data + 0x1f1, sizeof(boot->hdr));

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

  if ((uint64_t)KERNEL_LOAD_ADDR + kernel_size > s->data.kvm.guestmem_size) {
    errno = EFBIG;
    goto out;
  }

  memcpy((uint8_t*)s->data.kvm.guestmem + KERNEL_LOAD_ADDR,
         (uint8_t*)data + setup_size, kernel_size);

  uint64_t runtime_start = KERNEL_LOAD_ADDR;

  if (boot->hdr.relocatable_kernel) {
    if (runtime_start < boot->hdr.pref_address)
      runtime_start = boot->hdr.pref_address;

    if (boot->hdr.kernel_alignment)
      runtime_start = (runtime_start + boot->hdr.kernel_alignment - 1) &
                      ~((uint64_t)boot->hdr.kernel_alignment - 1);
  } else if (boot->hdr.pref_address) {
    runtime_start = boot->hdr.pref_address;
  }

  if (boot->hdr.init_size)
    kernel_end = runtime_start + boot->hdr.init_size;
  else
    kernel_end = runtime_start + kernel_size;

  if (kernel_end > s->data.kvm.guestmem_size) {
    errno = ENOMEM;
    goto out;
  }

  munmap(data, data_size);
  data = MAP_FAILED;
  data_size = 0;

  /* Command line. */
  {
#if DEBUG
    const char* cmdline = "console=ttyS0 acpi=off pci=off";
#else
    const char* cmdline = "acpi=off pci=off";
#endif
    size_t cmdline_len = strlen(cmdline) + 1;

    if (boot->hdr.cmdline_size != 0 && cmdline_len > boot->hdr.cmdline_size) {
      errno = E2BIG;
      goto out;
    }

    if ((uint64_t)CMDLINE_START + cmdline_len > s->data.kvm.guestmem_size) {
      errno = ENOMEM;
      goto out;
    }

    memcpy((uint8_t*)s->data.kvm.guestmem + CMDLINE_START, cmdline,
           cmdline_len);
  }

  /* Boot parameters. */
  boot->hdr.code32_start = KERNEL_LOAD_ADDR;
  boot->hdr.type_of_loader = 0xff;
  boot->hdr.cmd_line_ptr = CMDLINE_START;

  boot->e820_entries = 3;

  boot->e820_table[0].addr = 0x00000000;
  boot->e820_table[0].size = 0x0009fc00;
  boot->e820_table[0].type = 1;

  boot->e820_table[1].addr = 0x0009fc00;
  boot->e820_table[1].size = 0x00060400;
  boot->e820_table[1].type = 2;

  boot->e820_table[2].addr = 0x00100000;
  boot->e820_table[2].size = s->data.kvm.guestmem_size - 0x00100000;
  boot->e820_table[2].type = 1;

  /* Load initrd. */
  fd = open(s->data.kvm.initramfs_path, O_RDONLY);
  if (fd < 0) goto out;

  if (fstat(fd, &st) < 0) goto out;

  if (st.st_size <= 0 || (uint64_t)st.st_size > s->data.kvm.guestmem_size ||
      (uint64_t)st.st_size > UINT32_MAX) {
    errno = EFBIG;
    goto out;
  }

  data_size = st.st_size;
  data = mmap(NULL, data_size, PROT_READ, MAP_PRIVATE, fd, 0);
  if (data == MAP_FAILED) goto out;

  close(fd);
  fd = -1;

  initrd_top = s->data.kvm.guestmem_size;

  if (boot->hdr.initrd_addr_max != 0 &&
      initrd_top > (uint64_t)boot->hdr.initrd_addr_max + 1)
    initrd_top = (uint64_t)boot->hdr.initrd_addr_max + 1;

  if (initrd_top > 0x100000000ULL) initrd_top = 0x100000000ULL;

  if (data_size > initrd_top) {
    errno = ENOMEM;
    goto out;
  }

  initrd_addr64 = (initrd_top - data_size) & ~((uint64_t)INITRD_ALIGN - 1);

  if (initrd_addr64 < kernel_end) {
    errno = ENOMEM;
    goto out;
  }

  if (initrd_addr64 + data_size > s->data.kvm.guestmem_size) {
    errno = ENOMEM;
    goto out;
  }

  if (initrd_addr64 > UINT32_MAX) {
    errno = EOVERFLOW;
    goto out;
  }

  initrd_addr = (uint32_t)initrd_addr64;

  memcpy((uint8_t*)s->data.kvm.guestmem + initrd_addr, data, data_size);

  boot->hdr.ramdisk_image = initrd_addr;
  boot->hdr.ramdisk_size = (uint32_t)data_size;

  fprintf(stderr, "load=%llx pref=%llx runtime=%llx init_size=%x initrd=%x\n",
          (unsigned long long)KERNEL_LOAD_ADDR,
          (unsigned long long)boot->hdr.pref_address,
          (unsigned long long)runtime_start, boot->hdr.init_size, initrd_addr);

  ret = 0;

out:
  saved_errno = errno;

  if (data != MAP_FAILED) munmap(data, data_size);
  if (fd >= 0) close(fd);

  errno = saved_errno;
  return ret;
}

static int kvm_setup_guest_vcpu(int kvmfd, struct uav_sandbox* s) {
  struct {
    uint32_t nent;
    uint32_t padding;
    struct kvm_cpuid_entry2 entries[100];
  } kvm_cpuid;

  struct kvm_sregs sregs;
  struct kvm_regs regs;
  uint64_t* gdt;
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
  kvm_cpuid.nent = sizeof(kvm_cpuid.entries) / sizeof(kvm_cpuid.entries[0]);

  ret = ioctl(kvmfd, KVM_GET_SUPPORTED_CPUID, &kvm_cpuid);
  if (ret < 0) goto out;

  for (unsigned int i = 0; i < kvm_cpuid.nent; i++) {
    struct kvm_cpuid_entry2* entry = &kvm_cpuid.entries[i];

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
  gdt = (uint64_t*)((uint8_t*)s->data.kvm.guestmem + GDT_START);

  gdt[0] = 0x0000000000000000ULL; /* 0x00 null */
  gdt[1] = 0x0000000000000000ULL; /* 0x08 unused */
  gdt[2] = 0x00cf9a000000ffffULL; /* 0x10 code */
  gdt[3] = 0x00cf92000000ffffULL; /* 0x18 data */

  /* Setup vCPU special registers. */
  ret = ioctl(s->data.kvm.vcpufd, KVM_GET_SREGS, &sregs);
  if (ret < 0) goto out;

  sregs.gdt.base = GDT_START;
  sregs.gdt.limit = 4 * 8 - 1;

  /* Code segment (selector 0x10). */
  sregs.cs.base = 0;
  sregs.cs.limit = 0xffffffff;
  sregs.cs.selector = 0x10;
  sregs.cs.type = 0x0b;
  sregs.cs.present = 1;
  sregs.cs.dpl = 0;
  sregs.cs.db = 1;
  sregs.cs.s = 1;
  sregs.cs.l = 0;
  sregs.cs.g = 1;
  sregs.cs.avl = 0;

  /* Data segments (selector 0x18). */
  sregs.ds.base = 0;
  sregs.ds.limit = 0xffffffff;
  sregs.ds.selector = 0x18;
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
