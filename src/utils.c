#include <fcntl.h>
#include <ftw.h>
#include <linux/limits.h>
#include <string.h>
#include <unistd.h>

#include "utils.h"

static int unlink_cb(const char *fpath, const struct stat *sb, int typeflag, struct FTW *ftwbuf) {
  (void)sb;
  (void)typeflag;
  (void)ftwbuf;

  int rv = remove(fpath);

  if (rv) fprintf(stderr, "cannot remove %s: %s\n", fpath, strerror(errno));

  return rv;
}

/* Delete a directory recursively */
int rmtree(const char *path) {
  return nftw(path, unlink_cb, 64, FTW_DEPTH | FTW_PHYS);
}

/*
 * "/tmp"  + "work"   -> "/tmp/work"
 * "/tmp/" + "work"   -> "/tmp/work"
 * "/tmp"  + "/work"  -> "/tmp/work"
 * "/tmp/" + "/work"  -> "/tmp/work"
 */
char *uav_path_join(const char *p1, const char *p2) {
  if (p1 == NULL || p2 == NULL) {
    errno = EINVAL;
    return NULL;
  }
  size_t l1 = strnlen(p1, PATH_MAX);
  size_t l2 = strnlen(p2, PATH_MAX);

  if (l1 == PATH_MAX || l2 == PATH_MAX) {
    errno = ENAMETOOLONG;
    return NULL;
  }

  int p1_slash = l1 > 0 && p1[l1 - 1] == '/';
  int p2_slash = l2 > 0 && p2[l2 - 1] == '/';

  size_t skip = p1_slash && p2_slash ? 1 : 0;
  size_t add_slash = !p1_slash && !p2_slash ? 1 : 0;

  if (l1 > PATH_MAX - l2 - add_slash - 1 + skip) {
    errno = ENAMETOOLONG;
    return NULL;
  }

  size_t len = l1 + l2 + add_slash - skip;

  char *r = (char *)uav_malloc(len + 1);
  memcpy(r, p1, l1);

  size_t pos = l1;

  if (add_slash) r[pos++] = '/';

  memcpy(r + pos, p2 + skip, l2 - skip);
  pos += l2 - skip;

  r[pos] = '\0';
  return r;
}

int write_file(const char *path, const char *data, size_t len) {
  int fd, ret = -1, saved_errno;
  ssize_t written;

  fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
  if (fd < 0) goto cleanup;

  written = write(fd, data, len);
  if (written < 0) goto cleanup;
  if ((size_t)written != len) {
    errno = EIO;
    goto cleanup;
  }

  ret = 0;

cleanup:
  saved_errno = errno;
  if (fd >= 0)close(fd);
  errno = saved_errno;

  return ret;
}

int write_file_str(const char *path, const char *str) {
  return write_file(path, str, strlen(str));
}

int copyfile(const char *src, const char *dst) {
  static const char temp_name[] = ".uav-copy-XXXXXX";
  int srcfd = -1, dstfd = -1;
  unsigned char buf[8192];
  struct stat src_stat;
  char *temp_path = NULL;
  const char *slash;
  size_t dst_len;
  size_t dir_len;
  int renamed = 0;
  int ret = -1;
  int saved_errno;

  if (src == NULL || dst == NULL) {
    errno = EINVAL;
    return -1;
  }

  dst_len = strnlen(dst, PATH_MAX);
  if (dst_len == 0 || dst_len == PATH_MAX) {
    errno = ENAMETOOLONG;
    return -1;
  }

  srcfd = open(src, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
  if (srcfd < 0) {
    fprintf(stderr, "[UAV] cannot open source %s: %s\n", src, strerror(errno));
    goto cleanup;
  }

  if (fstat(srcfd, &src_stat) < 0)
    goto cleanup;

  if (!S_ISREG(src_stat.st_mode)) {
    errno = EINVAL;
    goto cleanup;
  }

  /*
   * Create the temporary file in the destination directory so rename()
   * cannot cross filesystems and replacement of dst is atomic.
   */
  slash = strrchr(dst, '/');
  dir_len = slash != NULL ? (size_t)(slash - dst) + 1 : 0;

  if (dir_len > PATH_MAX - sizeof(temp_name)) {
    errno = ENAMETOOLONG;
    goto cleanup;
  }

  temp_path = uav_malloc(dir_len + sizeof(temp_name));
  memcpy(temp_path, dst, dir_len);
  memcpy(temp_path + dir_len, temp_name, sizeof(temp_name));

  dstfd = mkostemp(temp_path, O_CLOEXEC);
  if (dstfd < 0) {
    fprintf(stderr, "[UAV] cannot create temporary destination for %s: %s\n", dst, strerror(errno));
    goto cleanup;
  }

  for (;;) {
    ssize_t nread;

    do {
      nread = read(srcfd, buf, sizeof(buf));
    } while (nread < 0 && errno == EINTR);

    if (nread < 0) {
      fprintf(stderr, "[UAV] read error: %s\n", strerror(errno));
      goto cleanup;
    }

    if (nread == 0)
      break;

    ssize_t written = 0;

    while (written < nread) {
      ssize_t nwrite;

      do {
        nwrite = write(dstfd, buf + written, (size_t)(nread - written));
      } while (nwrite < 0 && errno == EINTR);

      if (nwrite < 0) {
        fprintf(stderr, "[UAV] write error: %s\n", strerror(errno));
        goto cleanup;
      }

      if (nwrite == 0) {
        errno = EIO;
        fprintf(stderr, "[UAV] write made no progress\n");
        goto cleanup;
      }

      written += nwrite;
    }
  }

  if (fchmod(dstfd, src_stat.st_mode & 0777) < 0)
    goto cleanup;

  /* Surface delayed write errors before publishing the completed file. */
  if (close(dstfd) < 0) {
    dstfd = -1;
    goto cleanup;
  }
  dstfd = -1;

  if (rename(temp_path, dst) < 0) {
    fprintf(stderr, "[UAV] cannot publish destination %s: %s\n", dst, strerror(errno));
    goto cleanup;
  }

  renamed = 1;
  ret = 0;

cleanup:
  saved_errno = errno;

  if (srcfd >= 0)
    close(srcfd);

  if (dstfd >= 0)
    close(dstfd);

  if (temp_path != NULL && !renamed)
    unlink(temp_path);

  free(temp_path);
  errno = saved_errno;

  return ret;
}
