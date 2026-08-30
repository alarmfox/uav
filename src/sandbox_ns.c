#include <archive.h>
#include <archive_entry.h>
#include <errno.h>
#include <sched.h>
#include <stdio.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#include "config.h"
#include "sandbox.h"
#include "sandbox_protocol.h"
#include "utils.h"

static const char sandbox_entrypoint_script[] =
    "#!/bin/sh\n"
    "set -e\n"
    "\n"
    "ln -sf /proc/self/fd /dev/fd\n"
    "ln -sf /proc/self/fd/0 /dev/stdin\n"
    "ln -sf /proc/self/fd/1 /dev/stdout\n"
    "ln -sf /proc/self/fd/2 /dev/stderr\n"
    "ln -sf pts/ptmx /dev/ptmx\n"
    "\n"
    "if [ \"$#\" -gt 0 ]; then\n"
    "    exec \"$@\"\n"
    "else\n"
    "    exec /bin/sh\n"
    "fi\n";

static int uav_extract_initramfs(const char *archive_path, const char *base);
static int uav_get_realuid(uid_t *uid, gid_t *gid);
static int uav_setup_userns_mappings(pid_t pid, uid_t uid, gid_t gid);
static int uav_sandbox_become_root(void);
static int uav_sandbox_setup_overlay(const struct uav_sandbox *s);
static int uav_sandbox_prepare_runtime(const struct uav_sandbox *s);
static int uav_sandbox_pivot_root(const struct uav_sandbox *s);
static int uav_sandbox_copyfile(const struct uav_sandbox *s, const char *src, const char *dst);
static int uav_sandbox_exec_entrypoint(const char *program);
static int sandbox_entrypoint(void *ptr);

struct uav_sandbox_entrypoint_args {
  /* Pointer to configured uav_sandbox */
  const struct uav_sandbox *s;
  /* Path of the program to execute host-side */
  const char *program;
  /*  Control socket file descriptor */
  int control_fd;
};

int uav_sandbox_ns_create(struct uav_sandbox *s) {
  int ret = 0;

  /* Safe because there is _Static_assert in config.h */
  strcpy(s->path, UAV_SANDBOX_DIR "/uav_sandbox_XXXXXX");

  if(mkdtemp(s->path) == NULL) return 1;

  s->data.stack = uav_malloc(UAV_SANDBOX_NS_STACK_SIZE);

  /* Prepare overlay fs */
  char *paths[4] = { NULL };
  for (size_t i = 0; i < 4; ++i) {
    paths[i] = uav_path_join(s->path, subdirs[i]);
    if(!paths[i]) {
      fprintf(stderr, "[UAV] cannot join paths (%s, %s)\n", s->path, subdirs[i]);
      ret = 1;
      goto cleanup;
    }
    ret = mkdir(paths[i], 0755);

    if (ret != 0 && errno != EEXIST) {
      fprintf(stderr, "[UAV] mkdir(%s) failed: %s\n", paths[i], strerror(errno));
      goto cleanup;
    }
  }

  ret = uav_extract_initramfs(UAV_SANDBOX_INITRAMFS_PATH, paths[0]);
  if(ret) {
      fprintf(stderr, "[UAV] extract initramfs failed\n");
      goto cleanup;
  }

cleanup:
  for (size_t i = 0; i < 4; i++)
    if (paths[i] != NULL) free(paths[i]);

  return ret;
}

int uav_sandbox_ns_run(const struct uav_sandbox *s, const char *program) {
  pid_t child;
  int control_fd[2] = {-1, -1}, ret = 0;
  uid_t uid;
  gid_t gid;
  struct uav_sandbox_msg msg;
  int wstatus;

  ret = socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, control_fd);
  if (ret < 0) {
    fprintf(stderr, "[UAV] socketpair: %s\n", strerror(errno));
    return 1;
  }

  struct uav_sandbox_entrypoint_args *args = uav_malloc(sizeof(struct uav_sandbox_entrypoint_args));

  args->s = s;
  args->program = program;
  args->control_fd = control_fd[1];

  child = clone(sandbox_entrypoint, (char*)s->data.stack + UAV_SANDBOX_NS_STACK_SIZE,
      CLONE_NEWUSER |
      CLONE_NEWPID |
      CLONE_NEWNS |
      CLONE_NEWNET |
      CLONE_NEWUTS |
      CLONE_NEWIPC |
      CLONE_NEWCGROUP |
      SIGCHLD,
      args);

  if(child < 0) {
    ret = 1;
    fprintf(stderr, "[UAV] cannot clone: %s\n", strerror(errno));
    goto cleanup;
  }

  free(args);
  close(control_fd[1]);
  control_fd[1]= -1;

  /* UID-GID Mapping */
  ret = uav_get_realuid(&uid, &gid);
  if (ret) {
    uav_sandbox_send_msg(control_fd[0], MSG_PARENT_ERROR, errno);
    goto cleanup;
  }

  ret = uav_setup_userns_mappings(child, uid, gid);
  if (ret) {
    uav_sandbox_send_msg(control_fd[0], MSG_PARENT_ERROR, errno);
    goto cleanup;
  }

  ret = uav_sandbox_send_msg(control_fd[0], MSG_PARENT_MAPPINGS_DONE, 0);
  if (ret < 0) goto cleanup;

  /* Sync with child setup */
  ret = uav_sandbox_recv_msg(control_fd[0], &msg);
  if (ret < 0 || msg.type == MSG_CHILD_ERROR) {
    fprintf(stderr, "[UAV] child setup failed\n");
    goto cleanup;
  }

  ret = uav_sandbox_send_msg(control_fd[0], MSG_PARENT_GO, 0);
  if (ret < 0) goto cleanup;

  waitpid(child, &wstatus, 0);
  ret = (WIFEXITED(wstatus) && WEXITSTATUS(wstatus) == 0) ? 0 : 1;

cleanup:
  if (control_fd[0] > 0) {
    close(control_fd[0]);
    control_fd[0] = -1;
  }

  if (ret != 0 && child > 0) kill(child, SIGKILL);

  return ret;
}

void uav_sandbox_ns_destroy(struct uav_sandbox *s) {
  int ret;
  char *p = uav_path_join(s->path, "/merged");

  if (s == NULL) return;
  if (s->data.stack != NULL) {
    free(s->data.stack);
    s->data.stack = NULL;
  }

  free(p);
  p = NULL;

  ret = rmtree(s->path);
  if (ret) {
    fprintf(stderr, "[SANDBOX] cannot remove tree %s: %s\n", s->path, strerror(errno));
  }
}

static int uav_extract_initramfs(const char *archive_path, const char *base) {
  struct archive *a = NULL;
  struct archive *ext = NULL;
  struct archive_entry *entry;
  int ret = 1;

  a = archive_read_new();
  if (!a)
    return 1;

  archive_read_support_filter_gzip(a);
  archive_read_support_format_cpio(a);

  if (archive_read_open_filename(a, archive_path, 10240) != ARCHIVE_OK) {
    fprintf(stderr, "[UAV] cannot open %s: %s\n",archive_path, archive_error_string(a));
    goto out;
  }

  ext = archive_write_disk_new();
  if (!ext)
    goto out;

  archive_write_disk_set_options(
      ext,
      ARCHIVE_EXTRACT_TIME |
      ARCHIVE_EXTRACT_PERM |
      ARCHIVE_EXTRACT_ACL |
      ARCHIVE_EXTRACT_FFLAGS
      );

  while (archive_read_next_header(a, &entry) == ARCHIVE_OK) {
    const char *name = archive_entry_pathname(entry);

    char path[PATH_MAX];

    if (snprintf(path, sizeof(path), "%s/%s", base, name)
        >= (int)sizeof(path)) {
      fprintf(stderr, "[UAV] extracted path too long: %s\n", name);
      goto out;
    }

    archive_entry_set_pathname(entry, path);

    int r = archive_read_extract2(a, entry, ext);
    if (r != ARCHIVE_OK) {
      fprintf(stderr, "[UAV] extract %s failed: %s\n",
          path, archive_error_string(a));
      goto out;
    }
  }

  ret = 0;

out:
  if (ext)
    archive_write_free(ext);

  if (a) {
    archive_read_close(a);
    archive_read_free(a);
  }

  return ret;
}

/* Retrieve real uid and gid even if running with sudo */
static int uav_get_realuid(uid_t *uid, gid_t *gid) {
  const char *sudo_uid;
  const char *sudo_gid;
  char *end;
  unsigned long long value;
  int ret = -1;

  if (getuid() != 0) {
    *uid = getuid();
    *gid = getgid();
    ret = 0;
    goto out;
  }

  sudo_uid = secure_getenv("SUDO_UID");
  if (sudo_uid == NULL) {
    errno = ENOENT;
    goto out;
  }

  errno = 0;
  end = NULL;

  if (*sudo_uid == '-') {
    errno = EINVAL;
    goto out;
  }

  value = strtoull(sudo_uid, &end, 10);
  if (errno != 0) goto out;

  if (end == sudo_uid || *end != '\0' || value > (uid_t)-1) {
    errno = EINVAL;
    goto out;
  }

  *uid = (uid_t)value;

  sudo_gid = secure_getenv("SUDO_GID");
  if (sudo_gid == NULL) {
    errno = ENOENT;
    goto out;
  }

  errno = 0;
  end = NULL;
  value = strtoull(sudo_gid, &end, 10);
  if (errno != 0) goto out;

  if (end == sudo_gid || *end != '\0' || value > (gid_t)-1) {
    errno = EINVAL;
    goto out;
  }

  *gid = (gid_t)value;

  ret = 0;

out:
  return ret;
}

/* Setup user namespace UID/GID mapping before entering sandbox */
static int uav_setup_userns_mappings(pid_t pid, uid_t uid, gid_t gid) {
  char path[PATH_MAX];
  char mapping[256];
  int fd = -1;
  int ret = -1;
  int saved_errno;

  /* Write UID mapping: <inside-uid> <outside-uid> <count> */
  snprintf(path, sizeof(path), "/proc/%d/uid_map", pid);

  fd = open(path, O_WRONLY);
  if (fd < 0) goto out;

  snprintf(mapping, sizeof(mapping), "0 %d 1", uid);
  ret = write(fd, mapping, strlen(mapping));
  if (ret < 0) goto out;

  close(fd);
  fd = -1;

  /* Disable setgroups before writing gid_map. */
  snprintf(path, sizeof(path), "/proc/%d/setgroups", pid);

  fd = open(path, O_WRONLY);
  if (fd >= 0) {
    ret = write(fd, "deny", 4);
    if (ret < 0) goto out;

    close(fd);
    fd = -1;
  } else if (errno != ENOENT) {
    /*
     * setgroups may not exist on kernels/configurations where it
     * isn't required/supported. Other errors are real failures.
     */
    goto out;
  }

  /* Write GID mapping. */
  snprintf(path, sizeof(path), "/proc/%d/gid_map", pid);

  fd = open(path, O_WRONLY);
  if (fd < 0) goto out;

  snprintf(mapping, sizeof(mapping), "0 %d 1", gid);
  ret = write(fd, mapping, strlen(mapping));
  if (ret < 0) goto out;

  ret = 0;

out:
  saved_errno = errno;

  if (fd >= 0) close(fd);

  errno = saved_errno;
  return ret;
}

static int uav_sandbox_become_root(void) {
    if (setresgid(0, 0, 0) < 0)
        return -1;

    if (setresuid(0, 0, 0) < 0)
        return -1;

    return 0;
}

static int uav_sandbox_setup_overlay(const struct uav_sandbox *s) {
  char *paths[4] = { NULL };
  char opts[8 * 1024];
  int ret = -1;
  int n;

  for (size_t i = 0; i < 4; ++i) {
    paths[i] = uav_path_join(s->path, subdirs[i]);
  }

  n = snprintf(opts, sizeof(opts), "lowerdir=%s,upperdir=%s,workdir=%s",
    paths[0],
    paths[2],
    paths[3]
  );

  if (n < 0 || (size_t)n >= sizeof(opts)) {
    errno = ENAMETOOLONG;
    goto out;
  }

  ret = mount("overlay", paths[1], "overlay", 0, opts);
  if(ret < 0) goto out;

out:
  for (size_t i = 0; i < 4; ++i)
    free(paths[i]);
  return ret;
}

static int sandbox_mount_at_root(const char *newroot, const char *relative, mode_t mode, const char *source,
    const char *fstype,
    unsigned long flags,
    const char *data) {

  char *path = NULL;
  int ret = -1;

  path = uav_path_join(newroot, relative);

  ret = mkdir_if_missing(path, mode);
  if (ret < 0) goto out;

  ret = mount(source, path, fstype, flags, data);
  if (ret < 0) goto out;

  ret = 0;

out:
  free(path);
  return ret;
}

static int uav_sandbox_prepare_runtime(const struct uav_sandbox *s) {

  char *newroot = NULL;
  char *entrypoint = NULL;
  char *dev_path = NULL;
  char *pts_path = NULL;
  int ret = -1;

  newroot = uav_path_join(s->path, "/merged");

  ret = sandbox_mount_at_root(newroot, "/proc", 0555, "proc", "proc", MS_NOSUID | MS_NOEXEC | MS_NODEV, NULL);
  if (ret < 0) goto out;

  ret = sandbox_mount_at_root(newroot, "/sys", 0555, "sysfs", "sysfs", MS_NOSUID | MS_NOEXEC | MS_NODEV, NULL);
  if (ret < 0) goto out;

  ret = sandbox_mount_at_root(newroot, "/dev", 0755, "tmpfs", "tmpfs", MS_NOSUID, "mode=755");
  if (ret < 0) goto out;

  ret = sandbox_mount_at_root(newroot, "/tmp", 01777, "tmpfs", "tmpfs", MS_NOSUID | MS_NODEV, "mode=1777");
  if (ret < 0) goto out;

  dev_path = uav_path_join(newroot, "/dev");
  pts_path = uav_path_join(dev_path, "/pts");

  ret = mkdir_if_missing(pts_path, 0755);
  if (ret < 0) goto out;

  mount("devpts", pts_path, "devpts", MS_NOSUID | MS_NOEXEC, "newinstance,ptmxmode=0666,mode=0620");
  if(ret < 0) goto out;

  entrypoint = uav_path_join(newroot, "/entrypoint");
  ret = write_file_str(entrypoint, sandbox_entrypoint_script);
  if (ret < 0) goto out;

  ret = chmod(entrypoint, 0755);
  if (ret < 0) goto out;

  ret = 0;

out:
  free(pts_path);
  free(dev_path);
  free(entrypoint);
  free(newroot);

  return ret;
}

static int uav_sandbox_pivot_root(const struct uav_sandbox *s) {

  char *newroot = NULL;
  char *oldroot = NULL;
  int ret = -1;

  newroot = uav_path_join(s->path, "/merged");
  oldroot = uav_path_join(newroot, "/oldroot");

  ret = mkdir_if_missing(oldroot,0700);
  if(ret < 0) goto out;

  ret = syscall(SYS_pivot_root, newroot, oldroot);
  if(ret < 0) goto out;

  ret = chdir("/");
  if(ret < 0) goto out;

  ret = umount2("/oldroot", MNT_DETACH);
  if(ret < 0) goto out;

  ret = rmdir("/oldroot");
  if(ret < 0) goto out;

  ret = 0;
out:
  free(newroot);
  free(oldroot);
  return ret;
}

static int uav_sandbox_copyfile(const struct uav_sandbox *s, const char *src, const char *dst) {

  int ret = -1;
  char *newroot= uav_path_join(s->path, "/merged");
  char *dstpath = uav_path_join(newroot, dst);
  struct stat statbuf;

  ret = copyfile(src, dstpath);
  if (ret < 0) goto out;

  ret = stat(src, &statbuf);
  if (ret < 0) goto out;

  ret = chmod(dstpath,  statbuf.st_mode);
  if (ret < 0) goto out;

  ret = 0;

out:
  free(newroot);
  free(dstpath);

  return ret;

}

static int uav_sandbox_exec_entrypoint(const char *program) {
  char *const envp[] = {
    "PATH=/bin:/sbin:/usr/bin:/usr/sbin",
    "TERM=xterm",
    "HOME=/root",
    "PS1=(@\\h):\\w>",
    NULL
  };

  char *const argv[] = {
    "/entrypoint",
    (char*)program,
    NULL
  };

  execve("/entrypoint", argv, envp);

  return -1;
}

static int sandbox_entrypoint(void *ptr) {
  struct uav_sandbox_entrypoint_args *args = ptr;
  struct uav_sandbox_msg msg;
  const char *err_msg = NULL;
  int ret;

  /* Wait for parent mapping */
  ret = uav_sandbox_recv_msg(args->control_fd, &msg);
  if (ret < 0 || msg.type != MSG_PARENT_MAPPINGS_DONE) {
    err_msg = "recv_msg: mappings not done";
    goto fail;
  }

  ret = uav_sandbox_become_root();
  if (ret < 0) {
    err_msg = "become root in user namespace";
    goto fail;
  }

  ret = mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL);
  if (ret < 0) {
    err_msg = "make mount namespace private";
    goto fail;
  }

  ret = uav_sandbox_setup_overlay(args->s);
  if (ret < 0) {
    err_msg = "setup overlay";
    goto fail;
  }

  ret = uav_sandbox_prepare_runtime(args->s);
  if (ret < 0) {
    err_msg = "prepare runtime";
    goto fail;
  }

  /* Signal we are ready */
  ret = uav_sandbox_send_msg(args->control_fd, MSG_CHILD_READY, 0);
  if (ret < 0) {
    err_msg = "send_msg: READY";
    goto fail;
  }

  ret = uav_sandbox_recv_msg(args->control_fd, &msg);
  if (ret < 0 || msg.type != MSG_PARENT_GO) {
    err_msg = "recv_msg: GO";
    goto fail;
  }

  ret = uav_sandbox_copyfile(args->s, args->program, basename(args->program));
  if (ret < 0) {
    err_msg = "copyfile";
    goto fail;
  }

  ret = uav_sandbox_pivot_root(args->s);
  if (ret < 0) {
    err_msg = "pivot root";
    goto fail;
  }

  char *path = uav_path_join("/", basename(args->program));
  ret = uav_sandbox_exec_entrypoint(path);
  err_msg = "exec entrypoint";

fail:
  {
    int saved_errno = errno;

    fprintf(stderr,  "[UAV] sandbox failure at %s: %s\n", err_msg ? err_msg : "unknown", strerror(saved_errno));
    uav_sandbox_send_msg(args->control_fd, MSG_CHILD_ERROR,  saved_errno);
    _exit(1);
  }
}


