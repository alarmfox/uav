#ifndef __UAV_REPORT_H
#define __UAV_REPORT_H

#include <time.h>
#include <sys/types.h>
#include <limits.h>

struct uav_scanner;

/* File type classification based on magic numbers */
enum uav_filetype {
  UAV_FILE_UNKNOWN = 0,
  UAV_FILE_ELF,
  UAV_FILE_PDF,
  UAV_FILE_PNG,
  UAV_FILE_JPEG,
  UAV_FILE_ZIP,
  UAV_FILE_SCRIPT,
  UAV_FILE_PE,        /* Windows executable */
  UAV_FILE_MACHO,     /* macOS executable */
  UAV_FILE_TEXT,
};

/* Suspicion index: 0.0 (clean) to 1.0 (highly suspicious) */
struct uav_suspicion {
  /* Overall suspicion score */
  float index;
  /* Matched known malware signature */
  int signature_match;
  /* Unknown file type (slightly suspicious) */
  int unknown_filetype;
  /* Is executable format */
  int executable;
  /* Human-readable explanation */
  char reason[256];
};

/* Complete malware analysis report */
struct uav_report {
  /* File identification */
  char filepath[PATH_MAX];
  size_t filesize;
  mode_t filemode;
 
  /* Cryptographic hashes */
  unsigned char md5[16];
  unsigned char sha1[20];
  unsigned char sha256[32];
  int has_md5;
  int has_sha1;
  int has_sha256;

  /* File type detection */
  enum uav_filetype filetype;
  unsigned char magic[16];    /* First 16 bytes */
  size_t magic_len;

  /* Yara scan */
  struct uav_yara_match *yr_matches;
  size_t yr_nmatch;

  /* Metadata */
  time_t scan_time;
  struct uav_suspicion suspicion;

  /* Error tracking */
  int error_code;
  char error_msg[256];
};

/* Report generation and output */
int uav_report_generate(const struct uav_scanner *scanner, const char *filepath, struct uav_report *report);
void uav_report_print(const struct uav_report *report);
void uav_report_destroy(struct uav_report *report);

#endif /* __UAV_REPORT_H */
