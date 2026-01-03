#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>

#include <openssl/evp.h>

#include "report.h"
#include "scanner.h"
#include "utils.h"

/* Magic number patterns for file type detection */
struct magic_pattern {
  unsigned char bytes[8];
  size_t len;
  enum uav_filetype type;
};

static const struct magic_pattern magic_patterns[] = {
  {{0x7F, 'E', 'L', 'F'}, 4, UAV_FILE_ELF},
  {{0x89, 'P', 'N', 'G', 0x0D, 0x0A, 0x1A, 0x0A}, 8, UAV_FILE_PNG},
  {{0x25, 'P', 'D', 'F'}, 4, UAV_FILE_PDF},
  {{0xFF, 0xD8, 0xFF}, 3, UAV_FILE_JPEG},
  {{0x50, 0x4B, 0x03, 0x04}, 4, UAV_FILE_ZIP},
  {{'M', 'Z'}, 2, UAV_FILE_PE},
  {{0xCF, 0xFA, 0xED, 0xFE}, 4, UAV_FILE_MACHO},  /* Mach-O 32-bit */
  {{0xFE, 0xED, 0xFA, 0xCF}, 4, UAV_FILE_MACHO},  /* Mach-O 32-bit reverse */
  {{0xCF, 0xFA, 0xED, 0xFE}, 4, UAV_FILE_MACHO},  /* Mach-O 64-bit */
  {{'#', '!'}, 2, UAV_FILE_SCRIPT},
};

static const size_t num_patterns = sizeof(magic_patterns) / sizeof(magic_patterns[0]);

/* Detect file type from magic bytes */
static enum uav_filetype detect_filetype(const unsigned char *magic, size_t len) {
  if (!magic || len == 0) {
    return UAV_FILE_UNKNOWN;
  }

  /* Check against known patterns */
  for (size_t i = 0; i < num_patterns; i++) {
    if (len >= magic_patterns[i].len &&
        memcmp(magic, magic_patterns[i].bytes, magic_patterns[i].len) == 0) {
      return magic_patterns[i].type;
    }
  }

  /* Check if it looks like text (all printable ASCII or whitespace) */
  int is_text = 1;
  for (size_t i = 0; i < len && i < 512; i++) {
    unsigned char c = magic[i];
    if (!(c >= 0x20 && c <= 0x7E) && c != '\n' && c != '\r' && c != '\t') {
      is_text = 0;
      break;
    }
  }

  return is_text ? UAV_FILE_TEXT : UAV_FILE_UNKNOWN;
}

/* Compute all hashes in a single pass through the file */
static int compute_all_hashes(FILE *file, struct uav_report *report) {
  EVP_MD_CTX *md5_ctx = NULL, *sha1_ctx = NULL, *sha256_ctx = NULL;
  unsigned char buf[8192];
  size_t n;
  int ret = -1;
  unsigned int md5_len, sha1_len, sha256_len;

  if (!file || !report) {
    errno = EINVAL;
    return -1;
  }

  /* Initialize all contexts */
  md5_ctx = EVP_MD_CTX_new();
  sha1_ctx = EVP_MD_CTX_new();
  sha256_ctx = EVP_MD_CTX_new();

  if (!md5_ctx || !sha1_ctx || !sha256_ctx) {
    errno = ENOMEM;
    goto cleanup;
  }

  if (EVP_DigestInit_ex(md5_ctx, EVP_md5(), NULL) != 1 ||
      EVP_DigestInit_ex(sha1_ctx, EVP_sha1(), NULL) != 1 ||
      EVP_DigestInit_ex(sha256_ctx, EVP_sha256(), NULL) != 1) {
    snprintf(report->error_msg, sizeof(report->error_msg), 
        "Failed to initialize hash contexts");
    goto cleanup;
  }

  /* Single pass: update all digests */
  rewind(file);
  while ((n = fread(buf, 1, sizeof(buf), file)) > 0) {
    if (EVP_DigestUpdate(md5_ctx, buf, n) != 1 ||
        EVP_DigestUpdate(sha1_ctx, buf, n) != 1 ||
        EVP_DigestUpdate(sha256_ctx, buf, n) != 1) {
      snprintf(report->error_msg, sizeof(report->error_msg),
          "Failed to update hash digests");
      goto cleanup;
    }
  }

  if (ferror(file)) {
    snprintf(report->error_msg, sizeof(report->error_msg),
        "Error reading file: %s", strerror(errno));
    goto cleanup;
  }

  /* Finalize all digests */
  if (EVP_DigestFinal_ex(md5_ctx, report->md5, &md5_len) != 1 ||
      EVP_DigestFinal_ex(sha1_ctx, report->sha1, &sha1_len) != 1 ||
      EVP_DigestFinal_ex(sha256_ctx, report->sha256, &sha256_len) != 1) {
    snprintf(report->error_msg, sizeof(report->error_msg),
        "Failed to finalize hash digests");
    goto cleanup;
  }

  /* Verify expected lengths */
  if (md5_len != 16 || sha1_len != 20 || sha256_len != 32) {
    snprintf(report->error_msg, sizeof(report->error_msg),
        "Unexpected hash lengths");
    goto cleanup;
  }

  report->has_md5 = 1;
  report->has_sha1 = 1;
  report->has_sha256 = 1;
  ret = 0;

cleanup:
  EVP_MD_CTX_free(md5_ctx);
  EVP_MD_CTX_free(sha1_ctx);
  EVP_MD_CTX_free(sha256_ctx);
  return ret;
}

/* Calculate suspicion index based on various factors */
static void calculate_suspicion(struct uav_report *report, int sig_match) {
  float score = 0.0f;
  char reasons[256] = "";

  /* Known malware signature: maximum suspicion */
  if (sig_match) {
    score = 1.0f;
    strcat(reasons, "Matches known malware signature; ");
    report->suspicion.signature_match = 1;
  } else {
    report->suspicion.signature_match = 0;
  }

  /* Executable formats are more suspicious than data files */
  if (report->filetype == UAV_FILE_ELF ||
      report->filetype == UAV_FILE_PE ||
      report->filetype == UAV_FILE_MACHO ||
      report->filetype == UAV_FILE_SCRIPT) {
    score += 0.3f;
    strcat(reasons, "Executable format; ");
    report->suspicion.executable = 1;
  } else {
    report->suspicion.executable = 0;
  }

  /* Unknown file types are slightly suspicious */
  if (report->filetype == UAV_FILE_UNKNOWN) {
    score += 0.1f;
    strcat(reasons, "Unknown file type; ");
    report->suspicion.unknown_filetype = 1;
  } else {
    report->suspicion.unknown_filetype = 0;
  }

  /* Executable bit set on file */
  if (report->filemode & S_IXUSR) {
    score += 0.1f;
    strcat(reasons, "Executable permission set; ");
  }

  /* Cap at 1.0 */
  if (score > 1.0f) {
    score = 1.0f;
  }

  /* If clean, say so */
  if (score == 0.0f) {
    strcpy(reasons, "No suspicious indicators detected");
  } else {
    /* Remove trailing "; " */
    size_t len = strlen(reasons);
    if (len >= 2 && reasons[len-2] == ';') {
      reasons[len-2] = '\0';
    }
  }

  report->suspicion.index = score;
  safe_strcpy(report->suspicion.reason, reasons, sizeof(report->suspicion.reason));
}

/* Convert file type enum to human-readable string */
static const char *filetype_to_string(enum uav_filetype type) {
  switch (type) {
    case UAV_FILE_ELF: return "ELF executable";
    case UAV_FILE_PDF: return "PDF document";
    case UAV_FILE_PNG: return "PNG image";
    case UAV_FILE_JPEG: return "JPEG image";
    case UAV_FILE_ZIP: return "ZIP archive";
    case UAV_FILE_SCRIPT: return "Script (shebang)";
    case UAV_FILE_PE: return "Windows PE executable";
    case UAV_FILE_MACHO: return "macOS Mach-O executable";
    case UAV_FILE_TEXT: return "Text file";
    case UAV_FILE_UNKNOWN:
    default: return "Unknown";
  }
}

/* Generate complete malware report for a file */
int uav_report_generate(const struct uav_scanner *scanner, const char *filepath, struct uav_report *report) {
  FILE *file = NULL;
  struct stat st;
  int ret = -1;
  int sig_match = 0;

  if (!scanner || !filepath || !report) {
    errno = EINVAL;
    return -1;
  }

  /* Zero out report structure */
  memset(report, 0, sizeof(*report));
  report->scan_time = time(NULL);

  /* Copy filepath */
  if (realpath(filepath, report->filepath) == NULL) {
    safe_strcpy(report->filepath, filepath, sizeof(report->filepath));
  }

  /* Get file metadata */
  if (stat(filepath, &st) != 0) {
    report->error_code = errno;
    snprintf(report->error_msg, sizeof(report->error_msg),   "Cannot stat file: %s", strerror(errno));
    return -1;
  }

  report->filesize = st.st_size;
  report->filemode = st.st_mode;

  /* Open file for reading */
  file = fopen(filepath, "rb");
  if (!file) {
    report->error_code = errno;
    snprintf(report->error_msg, sizeof(report->error_msg),  "Cannot open file: %s", strerror(errno));
    return -1;
  }

  /* Read magic bytes */
  report->magic_len = fread(report->magic, 1, sizeof(report->magic), file);
  if (report->magic_len == 0 && ferror(file)) {
    report->error_code = errno;
    snprintf(report->error_msg, sizeof(report->error_msg), "Cannot read magic bytes: %s", strerror(errno));
    goto cleanup;
  }

  /* Detect file type */
  report->filetype = detect_filetype(report->magic, report->magic_len);

  /* Compute all cryptographic hashes */
  if (compute_all_hashes(file, report) != 0) {
    report->error_code = errno;
    /* error_msg already set by compute_all_hashes */
    goto cleanup;
  }

  /* TODO: Check against malware signature database if available */
  /* Scan imported against yara rules */
  if(scanner->rules) {
    struct uav_yara_match *matches;
    size_t nmatch;
    int ret;
    ret = uav_scanner_scan_file_sync(scanner, filepath, &matches, &nmatch);
    if(ret) {
      fprintf(stderr, "[YARA ERROR]\n");
      goto cleanup;
    }

    report->yr_matches = matches;
  }

  /* Calculate suspicion index */
  calculate_suspicion(report, sig_match);

  ret = 0;

cleanup:
  if (file) {
    fclose(file);
  }

  return ret;
}

/* Print report to stdout */
void uav_report_print(const struct uav_report *report) {
  if (!report) {
    fprintf(stderr, "Error: NULL report\n");
    return;
  }

  /* Print error if report generation failed */
  if (report->error_code != 0) {
    printf("=== Malware Analysis Report (ERROR) ===\n");
    printf("File: %s\n", report->filepath);
    printf("Error: %s\n", report->error_msg);
    return;
  }

  printf("=== Malware Analysis Report ===\n");
  printf("\n");

  /* File information */
  printf("File Information:\n");
  printf("  Path:        %s\n", report->filepath);
  printf("  Size:        %zu bytes\n", report->filesize);
  printf("  Type:        %s\n", filetype_to_string(report->filetype));
  printf("  Permissions: %04o\n", report->filemode & 0777);

  /* Magic bytes (hex dump) */
  printf("\n");
  printf("Magic Bytes: ");
  for (size_t i = 0; i < report->magic_len && i < 16; i++) {
    printf("%02x ", report->magic[i]);
  }
  printf("\n");

  /* Cryptographic hashes */
  printf("\n");
  printf("Cryptographic Hashes:\n");

  if (report->has_md5) {
    printf("  MD5:    ");
    for (int i = 0; i < 16; i++) {
      printf("%02x", report->md5[i]);
    }
    printf("\n");
  }

  if (report->has_sha1) {
    printf("  SHA-1:  ");
    for (int i = 0; i < 20; i++) {
      printf("%02x", report->sha1[i]);
    }
    printf("\n");
  }

  if (report->has_sha256) {
    printf("  SHA-256: ");
    for (int i = 0; i < 32; i++) {
      printf("%02x", report->sha256[i]);
    }
    printf("\n");
  }

  /* Suspicion analysis */
  printf("\n");
  printf("Suspicion Analysis:\n");
  printf("  Suspicion Index: %.2f (0.0=clean, 1.0=highly suspicious)\n", 
      report->suspicion.index);
  printf("  Assessment: ");

  if (report->suspicion.index >= 0.8f) {
    printf("HIGHLY SUSPICIOUS\n");
  } else if (report->suspicion.index >= 0.5f) {
    printf("SUSPICIOUS\n");
  } else if (report->suspicion.index >= 0.2f) {
    printf("MODERATELY SUSPICIOUS\n");
  } else {
    printf("LOW RISK\n");
  }

  printf("  Indicators:\n");
  printf("    - Signature match: %s\n", report->suspicion.signature_match ? "YES" : "no");
  printf("    - Executable format: %s\n", report->suspicion.executable ? "YES" : "no");
  printf("    - Unknown type: %s\n", report->suspicion.unknown_filetype ? "YES" : "no");
  printf("    - Yara rule matched: %lu\n", report->yr_nmatch);
  printf("  Reason: %s\n", report->suspicion.reason);

  /* Timestamp */
  char timebuf[64];
  struct tm *tm_info = localtime(&report->scan_time);
  strftime(timebuf, sizeof(timebuf), "%Y-%m-%d %H:%M:%S", tm_info);
  printf("\n");
  printf("Scan Time: %s\n", timebuf);
  printf("================================\n");
}


void uav_report_destroy(struct uav_report *report) {
  if(!report || report->yr_matches) return;

  free(report->yr_matches);
}
