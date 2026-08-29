#ifndef UAV_UTILS_H
#define UAV_UTILS_H

#include <errno.h>
#include <ftw.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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

#endif // !UAV_UTILS_H
