#ifndef __UAV_SCANNER_H
#define __UAV_SCANNER_H

#include <stddef.h>
#include <yara_x.h>

struct uav_yara_match {
    char rule_name[128];
};

struct uav_scanner {
  /* Each element of the array is a 32 byte digest */
  unsigned char (*signatures)[32];
  size_t sigcount;

  /* Yara */
  YRX_RULES* rules;
};

int uav_scanner_init(struct uav_scanner *s, const char *yr_path, const char *sig_path);
void uav_scanner_destroy(struct uav_scanner *s);
int uav_scanner_scan_file_sync(const struct uav_scanner *s, const char *path, struct uav_yara_match **matches, size_t *nmatch);

#endif // !__UAV_SCANNER_H
