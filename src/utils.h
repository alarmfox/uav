#ifndef UAV_UTILS_H
#define UAV_UTILS_H

#include <errno.h>
#include <fcntl.h>
#include <ftw.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <linux/limits.h>

/* Crash on out of memory */
static inline void* uav_malloc(size_t size) {
  void *p = malloc(size);
  if (p == NULL) {
    fprintf(stderr, "[UAV] out of memory (%s:%d)", __FILE__,  __LINE__);
    exit(2);
  }
  return p;
}

static int unlink_cb(const char *fpath, const struct stat *sb, int typeflag, struct FTW *ftwbuf) {
  (void)sb;
  (void)typeflag;
  (void)ftwbuf;

  int rv = remove(fpath);

  if (rv) fprintf(stderr, "cannot remove %s: %s\n", fpath, strerror(errno));

  return rv;
}

/* Delete a directory recursively */
static int rmtree(const char *path) {
  return nftw(path, unlink_cb, 64, FTW_DEPTH | FTW_PHYS);
}

/*
 * "/tmp"  + "work"   -> "/tmp/work"
 * "/tmp/" + "work"   -> "/tmp/work"
 * "/tmp"  + "/work"  -> "/tmp/work"
 * "/tmp/" + "/work"  -> "/tmp/work"
 */
static char *uav_path_join(const char *p1, const char *p2) {
  if (p1 == NULL || p2 == NULL) return NULL;
  size_t l1 = strnlen(p1, PATH_MAX);
  size_t l2 = strnlen(p2, PATH_MAX);

  if (l1 == PATH_MAX || l2 == PATH_MAX)
        return NULL;

  int p1_slash = l1 > 0 && p1[l1 - 1] == '/';
  int p2_slash = l2 > 0 && p2[l2 - 1] == '/';

  size_t skip = p1_slash && p2_slash ? 1 : 0;
  size_t add_slash = !p1_slash && !p2_slash ? 1 : 0;

  if (l1 > PATH_MAX - l2 - add_slash - 1 + skip)  return NULL;

  size_t len = l1 + l2 + add_slash - skip;

  char *r = (char *)uav_malloc(len);
  memcpy(r, p1, l1);

  size_t pos = l1;

  if (add_slash) r[pos++] = '/';

  memcpy(r + pos, p2 + skip, l2 - skip);
  pos += l2 - skip;

  r[pos] = '\0';
  return r;
}

static int write_file(const char *path, const char *data, size_t len) {
  int fd, ret = -1;
  ssize_t written;

  fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
  if (fd < 0) {
    fprintf(stderr, "[UTILS] cannot open %s: %s\n", path, strerror(errno));
    return -1;
  }

  written = write(fd, data, len);
  if (written < 0 || (size_t)written != len) {
    fprintf(stderr, "[UTILS] write failed: %s\n", strerror(errno));
    goto cleanup;
  }

  ret = 0;

cleanup:
  close(fd);
  return ret;
}

int write_file_str(const char *path, const char *str) {
  return write_file(path, str, strlen(str));
}

static inline int mkdir_if_missing(const char *path, mode_t mode) {
    if (mkdir(path, mode) == 0)
        return 0;

    if (errno == EEXIST)
        return 0;

    return -1;
}

static int copyfile(const char *src, const char *dst) {
  int srcfd = -1, dstfd = -1;
  unsigned char buf[8192];
  int ret = -1;

  srcfd = open(src, O_RDONLY);
  if (srcfd < 0) {
    fprintf(stderr, "[UAV] cannot open source %s: %s\n",
            src, strerror(errno));
    goto cleanup;
  }

  dstfd = open(dst, O_WRONLY | O_CREAT | O_TRUNC, 0644);
  if (dstfd < 0) {
    fprintf(stderr, "[UAV] cannot open destination %s: %s\n",
            dst, strerror(errno));
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
        nwrite = write(dstfd,
                       buf + written,
                       (size_t)(nread - written));
      } while (nwrite < 0 && errno == EINTR);

      if (nwrite < 0) {
        fprintf(stderr, "[UAV] write error: %s\n", strerror(errno));
        goto cleanup;
      }

      written += nwrite;
    }
  }

  ret = 0;

cleanup:
  if (srcfd >= 0)
    close(srcfd);

  if (dstfd >= 0)
    close(dstfd);

  return ret;
}

#endif // !UAV_UTILS_H
