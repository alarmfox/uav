#ifndef UAV_UTILS_H
#define UAV_UTILS_H

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>

/* Crash on out of memory */
static inline void* uav_malloc(size_t size) {
  void* p = malloc(size);
  if (p == NULL) {
    fprintf(stderr, "[UAV] out of memory (%s:%d)", __FILE__, __LINE__);
    exit(2);
  }
  return p;
}

static inline int mkdir_if_missing(const char* path, mode_t mode) {
  struct stat st;
  int ret = -1;

  ret = mkdir(path, mode);
  if (ret == 0) return 0;

  if (errno != EEXIST) return -1;

  ret = lstat(path, &st);
  if (ret < 0) return -1;

  if (!S_ISDIR(st.st_mode)) {
    errno = ENOTDIR;
    return -1;
  }

  return 0;
}

int uav_rmtree(const char* path);
char* uav_path_join(const char* p1, const char* p2);
int uav_write_all(int fd, const void* buf, size_t size);
int uav_write_file(const char* path, const unsigned char* data, size_t len);

#endif  // !UAV_UTILS_H
