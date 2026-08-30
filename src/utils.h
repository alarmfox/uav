#ifndef UAV_UTILS_H
#define UAV_UTILS_H

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>

/* Crash on out of memory */
static inline void* uav_malloc(size_t size) {
  void *p = malloc(size);
  if (p == NULL) {
    fprintf(stderr, "[UAV] out of memory (%s:%d)", __FILE__,  __LINE__);
    exit(2);
  }
  return p;
}

static inline int mkdir_if_missing(const char *path, mode_t mode) {
  if (mkdir(path, mode) == 0)
    return 0;

  if (errno == EEXIST)
    return 0;

  return -1;
}

int rmtree(const char *path);
char *uav_path_join(const char *p1, const char *p2);
int write_file(const char *path, const char *data, size_t len);
int write_file_str(const char *path, const char *str);
int copyfile(const char *src, const char *dst);

#endif // !UAV_UTILS_H
