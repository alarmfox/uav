#include <archive.h>
#include <archive_entry.h>
#include <linux/sched.h>
#include <sched.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#include "config.h"
#include "sandbox.h"
#include "utils.h"

static int uav_extract_initramfs(const char *archive_path, const char *base)
{
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

int uav_sandbox_create(struct uav_sandbox *s) {
  int ret = 0, n;
  char opts[8 * 1024];

  /* Safe because there is _Static_assert in config.h */
  strcpy(s->path, UAV_SANDBOX_DIR "/uav_sandbox_XXXXXX");

  if(mkdtemp(s->path) == NULL) return 1;

  s->stack = uav_malloc(UAV_SANDBOX_STACK_SIZE);

  /* Prepare overlay fs */
  static const char *subdirs[] = { "/base","/merged", "/upper", "/work"};
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

  n = snprintf(opts, sizeof(opts), "lowerdir=%s,upperdir=%s,workdir=%s", paths[0], paths[2], paths[3]);

  if (n < 0 || (size_t)n >= sizeof(opts)) {
    fprintf(stderr, "[UAV] overlay mount options too long\n");
    ret = 1;
    goto cleanup;
  }

  ret = mount("overlay", paths[1], "overlay", 0, opts);

  if (ret != 0) {
      fprintf(stderr, "[UAV] mount (%s) failed: %s\n", s->path, strerror(errno));
      goto cleanup;
  }

cleanup:
  for (size_t i = 0; i < 4; i++)
    if (paths[i] != NULL) free(paths[i]);

  return ret;
}

int uav_sandbox_run_program(const struct uav_sandbox *s, const char *program) {

  pid_t child;

  child = clone(0, s->stack + UAV_SANDBOX_STACK_SIZE,
      CLONE_NEWUSER |
      CLONE_NEWPID |
      CLONE_NEWNS |
      CLONE_NEWNET |
      CLONE_NEWUTS |
      CLONE_NEWIPC |
      CLONE_NEWCGROUP |
      SIGCHLD,
      0);

  return 0;
}

void uav_sandbox_destroy(struct uav_sandbox *s) {

  int ret;
  char *p = uav_path_join(s->path, "/merged");

  if (s == NULL) return;
  if (s->stack != NULL) {
    free(s->stack);
    s->stack = NULL;
  }

  ret = umount2(p, MNT_FORCE | MNT_DETACH);
  if (ret && errno != EINVAL) {
    fprintf(stderr, "[SANDBOX] cannot unmount %s: %s\n", s->path, strerror(errno));
  }

  free(p);

  ret = rmtree(s->path);
  if (ret) {
    fprintf(stderr, "[SANDBOX] cannot remove tree %s: %s\n", s->path, strerror(errno));
  }
}
