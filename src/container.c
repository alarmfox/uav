#include <archive.h>
#include <archive_entry.h>
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <stdio.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#include "config.h"
#include "agent_protocol.h"
#include "sandbox.h"
#include "transport.h"
#include "utils.h"

static const char* subdirs[] = {"/base", "/merged", "/upper", "/work"};

static pid_t waitpid_nointr(pid_t pid, int* status);
static int uav_extract_initramfs(const char* archive_path, const char* base);
static int uav_get_realuid(uid_t* uid, gid_t* gid);
static int uav_setup_userns_mappings(pid_t pid, uid_t uid, gid_t gid);

static int uav_sandbox_become_root(void);
static int uav_sandbox_setup_overlay(const struct uav_sandbox* s);
static int uav_sandbox_prepare_runtime(const struct uav_sandbox* s);
static int uav_sandbox_pivot_root(const struct uav_sandbox* s);
static int sandbox_entrypoint(void* ptr);

struct uav_sandbox_entrypoint_args {
  /* Pointer to configured uav_sandbox */
  const struct uav_sandbox* s;

  /* Socketpair descriptors inherited by the child. */
  int host_fd;
  int control_fd;
};

int uav_sandbox_ns_create(struct uav_sandbox* s) {
  char* paths[4] = {NULL, NULL, NULL, NULL};
  int ret = -1;
  int saved_errno;
  int control_fd[2] = {-1, -1};
  pid_t child = -1;
  struct uav_sandbox_entrypoint_args* args = NULL;
  uid_t uid;
  gid_t gid;
  struct uav_proto_msg msg;

  if (s == NULL) {
    errno = EINVAL;
    goto cleanup;
  }

  s->data.container.child = -1;

  /* Safe because there is a _Static_assert in config.h. */
  strcpy(s->data.container.path, UAV_SANDBOX_DIR "/uav_sandbox_XXXXXX");

  if (mkdtemp(s->data.container.path) == NULL) {
    s->data.container.path[0] = '\0';
    goto cleanup;
  }

  s->data.container.stack = uav_malloc(UAV_SANDBOX_NS_STACK_SIZE);

  /* Prepare OverlayFS directories. */
  for (size_t i = 0; i < 4; ++i) {
    paths[i] = uav_path_join(s->data.container.path, subdirs[i]);
    if (paths[i] == NULL) {
      errno = ENAMETOOLONG;
      fprintf(stderr, "[UAV] cannot join paths (%s, %s)\n",
              s->data.container.path, subdirs[i]);
      goto cleanup;
    }

    if (mkdir(paths[i], 0755) < 0 && errno != EEXIST) {
      fprintf(stderr, "[UAV] mkdir(%s) failed: %s\n", paths[i],
              strerror(errno));
      goto cleanup;
    }
  }

  ret = uav_extract_initramfs(UAV_SANDBOX_INITRAMFS_PATH, paths[0]);
  if (ret != 0) {
    fprintf(stderr, "[UAV] extract initramfs failed\n");
    goto cleanup;
  }

  if (socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, control_fd) < 0) {
    fprintf(stderr, "[UAV] socketpair: %s\n", strerror(errno));
    goto cleanup;
  }

  /* Store host side of the control_fd in struct uav_sandbox */
  args = uav_malloc(sizeof(*args));
  args->s = s;
  args->host_fd = control_fd[0];
  args->control_fd = control_fd[1];

  child = clone(sandbox_entrypoint,
                (char*)s->data.container.stack + UAV_SANDBOX_NS_STACK_SIZE,
                CLONE_NEWUSER | CLONE_NEWPID | CLONE_NEWNS | CLONE_NEWNET |
                    CLONE_NEWUTS | CLONE_NEWIPC | CLONE_NEWCGROUP | SIGCHLD,
                args);

  if (child < 0) {
    fprintf(stderr, "[UAV] cannot clone: %s\n", strerror(errno));
    goto cleanup;
  }

  /*
   * clone() did not use CLONE_VM, so the child has its own copy of args.
   */
  free(args);
  args = NULL;

  close(control_fd[1]);
  control_fd[1] = -1;

  s->trans = uav_fd_transport_create(control_fd[0]);
  if (s->trans == NULL) goto cleanup;
  control_fd[0] = -1;

  ret = uav_get_realuid(&uid, &gid);
  if (ret != 0) goto cleanup;

  ret = uav_setup_userns_mappings(child, uid, gid);
  if (ret != 0) goto cleanup;

  ret = uav_proto_send(s->trans, UAV_MSG_READY, NULL, 0);
  if (ret < 0) goto cleanup;

  ret = uav_proto_recv(s->trans, &msg);
  if (ret < 0) goto cleanup;

  if (msg.type == UAV_MSG_ERROR) {
    int remote_error;

    fprintf(stderr, "[UAV] child setup failed\n");
    if (uav_proto_decode_error(&msg, &remote_error) == 0) errno = remote_error;
    ret = -1;
    goto cleanup;
  }

  if (msg.type != UAV_MSG_READY) {
    fprintf(stderr, "[UAV] unexpected child message: %u\n", msg.type);
    errno = EPROTO;
    ret = -1;
    goto cleanup;
  }

  ret = 0;
  s->data.container.child = child;

cleanup:
  saved_errno = errno;

  if (args != NULL) free(args);

  if (control_fd[1] >= 0) close(control_fd[1]);

  if (control_fd[0] >= 0) close(control_fd[0]);

  if (ret < 0 && child > 0) {
    if (kill(child, SIGKILL) < 0 && errno != ESRCH) {
      fprintf(stderr, "[UAV] cannot kill child %d: %s\n", child,
              strerror(errno));
    } else if (waitpid_nointr(child, NULL) < 0 && errno != ECHILD) {
      fprintf(stderr, "[UAV] cannot reap child %d: %s\n", child,
              strerror(errno));
    }
  }

  for (size_t i = 0; i < 4; ++i)
    if (paths[i] != NULL) free(paths[i]);

  if (ret < 0) errno = saved_errno != 0 ? saved_errno : EIO;

  return ret;
}

int uav_sandbox_ns_run(const struct uav_sandbox* s, const char* program) {
  int ret = -1;
  int fd = -1;
  int saved_errno;
  struct stat st;
  struct uav_upload_meta meta;

  if (s == NULL || program == NULL) {
    errno = EINVAL;
    return -1;
  }

  fd = open(program, O_RDONLY | O_NOFOLLOW);
  if (fd < 0) {
    ret = -1;
    goto cleanup;
  }
  ret = fstat(fd, &st);
  if (ret < 0) goto cleanup;

  if (!S_ISREG(st.st_mode)) {
    errno = EINVAL;
    goto cleanup;
  }
  if (st.st_size <= 0 || (uintmax_t)st.st_size > UINT32_MAX) {
    errno = EFBIG;
    goto cleanup;
  }

  meta.size = (uint32_t)st.st_size;
  meta.source_mode = (uint32_t)st.st_mode & 0777U;
  meta.purpose = UAV_UPLOAD_EXECUTABLE;

  ret = uav_proto_upload(s->trans, fd, &meta);
  if (ret != 0) goto cleanup;

  ret = uav_proto_send(s->trans, UAV_MSG_RUN, NULL, 0);
  if (ret != 0) goto cleanup;

  for (;;) {
    struct uav_proto_msg msg;

    ret = uav_proto_recv(s->trans, &msg);
    if (ret < 0) goto cleanup;

    if (msg.type == UAV_MSG_EVENT) continue;

    if (msg.type == UAV_MSG_EXIT) {
      int status;

      if (uav_proto_decode_exit(&msg, &status) < 0) goto cleanup;

      if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        errno = EIO;
        ret = -1;
        goto cleanup;
      }

      ret = 0;
      break;
    }

    if (msg.type == UAV_MSG_ERROR) {
      int remote_error;

      if (uav_proto_decode_error(&msg, &remote_error) == 0)
        errno = remote_error;
      ret = -1;
      goto cleanup;
    }

    errno = EPROTO;
    ret = -1;
    goto cleanup;
  }

cleanup:
  saved_errno = errno;
  if (fd >= 0) close(fd);

  errno = saved_errno;

  return ret;
}

int uav_sandbox_ns_destroy(struct uav_sandbox* s) {
  int ret = 0;
  int saved_errno = 0;
  int graceful_exit = 0;

  if (s == NULL) {
    errno = EINVAL;
    return -1;
  }

  if (s->data.container.child > 0) {
    if (s->trans && uav_proto_send(s->trans, UAV_MSG_EXIT, NULL, 0) == 0) {
      graceful_exit = 1;
    }

    if (!graceful_exit && kill(s->data.container.child, SIGKILL) < 0 &&
        errno != ESRCH) {
      fprintf(stderr, "[UAV] cannot kill child %d: %s\n",
              s->data.container.child, strerror(errno));
      ret = -1;
      saved_errno = errno;
    }

    if (waitpid_nointr(s->data.container.child, NULL) < 0 && errno != ECHILD) {
      fprintf(stderr, "[UAV] cannot reap child %d: %s\n",
              s->data.container.child, strerror(errno));
      if (ret == 0) {
        ret = -1;
        saved_errno = errno;
      }
    } else {
      s->data.container.child = -1;
    }
  }

  if (s->data.container.stack != NULL) {
    free(s->data.container.stack);
    s->data.container.stack = NULL;
  }

  if (s->data.container.path[0] != '\0') {
    if (uav_rmtree(s->data.container.path) < 0) {
      fprintf(stderr, "[UAV] cannot remove tree %s: %s\n",
              s->data.container.path, strerror(errno));
      if (ret == 0) {
        ret = -1;
        saved_errno = errno;
      }
    } else {
      s->data.container.path[0] = '\0';
    }
  }

  if (ret < 0) errno = saved_errno;

  return ret;
}

static pid_t waitpid_nointr(pid_t pid, int* status) {
  pid_t result;

  do {
    result = waitpid(pid, status, 0);
  } while (result < 0 && errno == EINTR);

  return result;
}

static int uav_extract_initramfs(const char* archive_path, const char* base) {
  struct archive* a = NULL;
  struct archive* ext = NULL;
  struct archive_entry* entry;
  int archive_fd = -1;
  int cwd_fd = -1;
  int base_fd = -1;
  int cwd_changed = 0;
  int ar;
  int ret = -1;
  int saved_errno;

  /*
   * Open everything before chdir(), because archive_path may be relative.
   * O_NOFOLLOW prevents the final path component from being a symlink.
   */
  archive_fd = open(archive_path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
  if (archive_fd < 0) {
    fprintf(stderr, "[UAV] cannot open %s: %s\n", archive_path,
            strerror(errno));
    goto out;
  }

  cwd_fd = open(".", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
  if (cwd_fd < 0) {
    fprintf(stderr, "[UAV] cannot save working directory: %s\n",
            strerror(errno));
    goto out;
  }

  base_fd = open(base, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
  if (base_fd < 0) {
    fprintf(stderr, "[UAV] cannot open extraction directory %s: %s\n", base,
            strerror(errno));
    goto out;
  }

  a = archive_read_new();
  if (a == NULL) {
    fprintf(stderr, "[UAV] cannot allocate archive reader\n");
    errno = ENOMEM;
    goto out;
  }

  archive_read_support_filter_gzip(a);
  archive_read_support_format_cpio(a);

  ar = archive_read_open_fd(a, archive_fd, 10240);
  if (ar != ARCHIVE_OK) {
    fprintf(stderr, "[UAV] cannot read %s: %s\n", archive_path,
            archive_error_string(a));
    errno = EIO;
    goto out;
  }

  ext = archive_write_disk_new();
  if (ext == NULL) {
    fprintf(stderr, "[UAV] cannot allocate archive extractor\n");
    errno = ENOMEM;
    goto out;
  }

  ar = archive_write_disk_set_options(
      ext, ARCHIVE_EXTRACT_TIME | ARCHIVE_EXTRACT_PERM | ARCHIVE_EXTRACT_ACL |
               ARCHIVE_EXTRACT_FFLAGS | ARCHIVE_EXTRACT_SECURE_NODOTDOT |
               ARCHIVE_EXTRACT_SECURE_SYMLINKS |
               ARCHIVE_EXTRACT_SECURE_NOABSOLUTEPATHS);
  if (ar != ARCHIVE_OK) {
    fprintf(stderr, "[UAV] cannot configure archive extractor: %s\n",
            archive_error_string(ext));
    errno = EIO;
    goto out;
  }

  /*
   * From this point, relative archive paths resolve inside base.
   * Do not rewrite archive_entry_pathname().
   */
  if (fchdir(base_fd) < 0) {
    fprintf(stderr, "[UAV] cannot enter extraction directory: %s\n",
            strerror(errno));
    goto out;
  }
  cwd_changed = 1;

  while ((ar = archive_read_next_header(a, &entry)) == ARCHIVE_OK) {
    const char* name = archive_entry_pathname(entry);

    ar = archive_read_extract2(a, entry, ext);
    if (ar != ARCHIVE_OK) {
      fprintf(stderr, "[UAV] cannot extract %s: %s\n",
              name != NULL ? name : "(unknown)", archive_error_string(a));
      errno = EIO;
      goto out;
    }
  }

  /*
   * Anything other than ARCHIVE_EOF is a truncated or malformed archive,
   * not successful completion.
   */
  if (ar != ARCHIVE_EOF) {
    fprintf(stderr, "[UAV] archive read failed: %s\n", archive_error_string(a));
    errno = EIO;
    goto out;
  }

  ret = 0;

out:
  saved_errno = errno;

  /*
   * Finish extraction while paths are still relative to base.
   */
  if (ext != NULL) archive_write_free(ext);

  if (a != NULL) {
    archive_read_close(a);
    archive_read_free(a);
  }

  if (cwd_changed && fchdir(cwd_fd) < 0) {
    fprintf(stderr, "[UAV] cannot restore working directory: %s\n",
            strerror(errno));
    saved_errno = errno;
    ret = -1;
  }

  if (base_fd >= 0) close(base_fd);

  if (cwd_fd >= 0) close(cwd_fd);

  /*
   * archive_read_open_fd() does not transfer ownership of the descriptor.
   */
  if (archive_fd >= 0) close(archive_fd);

  if (ret < 0) errno = saved_errno != 0 ? saved_errno : EIO;

  return ret;
}

/* Retrieve real uid and gid even if running with sudo */
static int uav_get_realuid(uid_t* uid, gid_t* gid) {
  const char* sudo_uid;
  const char* sudo_gid;
  char* end;
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
  if (setresgid(0, 0, 0) < 0) return -1;

  if (setresuid(0, 0, 0) < 0) return -1;

  return 0;
}

static int uav_sandbox_setup_overlay(const struct uav_sandbox* s) {
  char* paths[4] = {NULL};
  char opts[8 * 1024];
  int ret = -1;
  int n;

  for (size_t i = 0; i < 4; ++i) {
    paths[i] = uav_path_join(s->data.container.path, subdirs[i]);
  }

  n = snprintf(opts, sizeof(opts), "lowerdir=%s,upperdir=%s,workdir=%s",
               paths[0], paths[2], paths[3]);

  if (n < 0 || (size_t)n >= sizeof(opts)) {
    errno = ENAMETOOLONG;
    goto out;
  }

  ret = mount("overlay", paths[1], "overlay", 0, opts);
  if (ret < 0) goto out;

out:
  for (size_t i = 0; i < 4; ++i) free(paths[i]);
  return ret;
}

static int sandbox_mount_at_root(const char* newroot, const char* relative,
                                 mode_t mode, const char* source,
                                 const char* fstype, unsigned long flags,
                                 const char* data) {
  char* path = NULL;
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

static int uav_sandbox_prepare_runtime(const struct uav_sandbox* s) {
  char* newroot = NULL;
  char* dev_path = NULL;
  char* pts_path = NULL;
  int ret = -1;

  newroot = uav_path_join(s->data.container.path, "/merged");

  ret = sandbox_mount_at_root(newroot, "/proc", 0555, "proc", "proc",
                              MS_NOSUID | MS_NOEXEC | MS_NODEV, NULL);
  if (ret < 0) goto out;

  ret = sandbox_mount_at_root(newroot, "/sys", 0555, "sysfs", "sysfs",
                              MS_NOSUID | MS_NOEXEC | MS_NODEV, NULL);
  if (ret < 0) goto out;

  ret = sandbox_mount_at_root(newroot, "/dev", 0755, "tmpfs", "tmpfs",
                              MS_NOSUID, "mode=755");
  if (ret < 0) goto out;

  ret = sandbox_mount_at_root(newroot, "/tmp", 01777, "tmpfs", "tmpfs",
                              MS_NOSUID | MS_NODEV, "mode=1777");
  if (ret < 0) goto out;

  ret = sandbox_mount_at_root(newroot, "/run", 0755, "tmpfs", "tmpfs",
                              MS_NOSUID | MS_NODEV, "mode=755");
  if (ret < 0) goto out;

  dev_path = uav_path_join(newroot, "/dev");
  pts_path = uav_path_join(dev_path, "/pts");

  ret = mkdir_if_missing(pts_path, 0755);
  if (ret < 0) goto out;

  mount("devpts", pts_path, "devpts", MS_NOSUID | MS_NOEXEC,
        "newinstance,ptmxmode=0666,mode=0620");
  if (ret < 0) goto out;

  ret = 0;

out:
  free(pts_path);
  free(dev_path);
  free(newroot);

  return ret;
}

static int uav_sandbox_pivot_root(const struct uav_sandbox* s) {
  char* newroot = NULL;
  char* oldroot = NULL;
  int ret = -1;

  newroot = uav_path_join(s->data.container.path, "/merged");
  oldroot = uav_path_join(newroot, "/oldroot");

  ret = mkdir_if_missing(oldroot, 0700);
  if (ret < 0) goto out;

  ret = syscall(SYS_pivot_root, newroot, oldroot);
  if (ret < 0) goto out;

  ret = chdir("/");
  if (ret < 0) goto out;

  ret = umount2("/oldroot", MNT_DETACH);
  if (ret < 0) goto out;

  ret = rmdir("/oldroot");
  if (ret < 0) goto out;

  ret = 0;
out:
  free(newroot);
  free(oldroot);
  return ret;
}

static int uav_sandbox_exec_entrypoint(int control_fd) {
  char fd_string[32];
  int flags;

  flags = fcntl(control_fd, F_GETFD);
  if (flags < 0) return -1;

  if (fcntl(control_fd, F_SETFD, flags & ~FD_CLOEXEC) < 0) return -1;

  snprintf(fd_string, sizeof(fd_string), "%d", control_fd);

  char* const envp[] = {"PATH=/bin:/sbin:/usr/bin:/usr/sbin", "TERM=xterm",
                        "HOME=/root", "PS1=(@\\h):\\w>", NULL};

  char* const argv[] = {"/sbin/uav-agent", "--control-fd", fd_string, NULL};

  execve("/sbin/uav-agent", argv, envp);

  return -1;
}

static int sandbox_entrypoint(void* ptr) {
  struct uav_sandbox_entrypoint_args* args = ptr;
  struct uav_transport* transport = NULL;
  struct uav_proto_msg msg;
  const char* err_msg = NULL;
  int ret;

  /* Close host side */
  close(args->host_fd);

  transport = uav_fd_transport_create(args->control_fd);
  if (transport == NULL) _exit(1);

  /* Wait for parent mapping */
  ret = uav_proto_recv(transport, &msg);
  if (ret < 0 || msg.type != UAV_MSG_READY) {
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

  ret = uav_sandbox_pivot_root(args->s);
  if (ret < 0) {
    err_msg = "pivot root";
    goto fail;
  }

  ret = uav_sandbox_exec_entrypoint(args->control_fd);
  err_msg = "exec entrypoint";

fail: {
  int saved_errno = errno;

  fprintf(stderr, "[UAV] sandbox failure at %s: %s\n",
          err_msg ? err_msg : "unknown", strerror(saved_errno));
  uav_proto_send_error(transport, saved_errno);
  uav_transport_destroy(&transport);
  _exit(1);
}
}
