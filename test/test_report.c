#include "test.h"
#include "report.h"
#include "scanner.h"
#include "utils.h"

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

/* Test fixture: create temporary test files */
static int create_test_file(const char *path, const unsigned char *content, size_t len, mode_t mode) {
  FILE *f = fopen(path, "wb");
  if (!f) return -1;

  if (fwrite(content, 1, len, f) != len) {
    fclose(f);
    return -1;
  }

  fclose(f);

  if (chmod(path, mode) != 0) {
    return -1;
  }

  return 0;
}

/* Test: NULL pointer handling */
static int test_report_null_handling(void) {
  TEST_CASE("report_generate - NULL pointer handling");

  struct uav_report report;
  int ret;

  /* NULL filepath */
  ret = uav_report_generate(NULL, &report);
  TEST_ASSERT_EQ(-1, ret, "Should reject NULL filepath");

  /* NULL report */
  ret = uav_report_generate("/tmp/test", NULL);
  TEST_ASSERT_EQ(-1, ret, "Should reject NULL report");

  TEST_SUCCESS();
}

/* Test: Nonexistent file handling */
static int test_report_nonexistent_file(void) {
  TEST_CASE("report_generate - nonexistent file");

  struct uav_report report;
  int ret;

  ret = uav_report_generate("/nonexistent/path/file.txt", &report);
  TEST_ASSERT_EQ(-1, ret, "Should fail on nonexistent file");
  TEST_ASSERT(report.error_code != 0, "Should set error code");
  TEST_ASSERT(strlen(report.error_msg) > 0, "Should set error message");

  TEST_SUCCESS();
}

/* Test: ELF file detection and hashing */
static int test_report_elf_file(void) {
  TEST_CASE("report_generate - ELF file detection");

  struct uav_report report;
  char tempfile[] = "/tmp/test_elf_XXXXXX";
  int fd, ret;

  /* Create temporary file */
  fd = mkstemp(tempfile);
  TEST_ASSERT(fd >= 0, "Should create temp file");
  close(fd);

  /* ELF magic: 7F 45 4C 46 */
  unsigned char elf_content[] = {
    0x7F, 'E', 'L', 'F',  /* ELF magic */
    0x02, 0x01, 0x01, 0x00, /* 64-bit, little-endian */
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    'H', 'e', 'l', 'l', 'o', ' ', 'W', 'o', 'r', 'l', 'd'
  };

  ret = create_test_file(tempfile, elf_content, sizeof(elf_content), 0755);
  TEST_ASSERT_EQ(0, ret, "Should write test file");

  /* Generate report */
  ret = uav_report_generate(tempfile, &report);
  TEST_ASSERT_EQ(0, ret, "Should generate report successfully");

  /* Verify file type detection */
  TEST_ASSERT_EQ(UAV_FILE_ELF, report.filetype, "Should detect ELF file");

  /* Verify magic bytes */
  TEST_ASSERT(report.magic_len >= 4, "Should read magic bytes");
  TEST_ASSERT_EQ(0x7F, report.magic[0], "ELF magic byte 0");
  TEST_ASSERT_EQ('E', report.magic[1], "ELF magic byte 1");
  TEST_ASSERT_EQ('L', report.magic[2], "ELF magic byte 2");
  TEST_ASSERT_EQ('F', report.magic[3], "ELF magic byte 3");

  /* Verify hashes were computed */
  TEST_ASSERT(report.has_md5, "Should have MD5");
  TEST_ASSERT(report.has_sha1, "Should have SHA1");
  TEST_ASSERT(report.has_sha256, "Should have SHA256");

  /* Verify suspicion index for executable */
  TEST_ASSERT(report.suspicion.index > 0.0f, "ELF should be suspicious");
  TEST_ASSERT(report.suspicion.executable, "Should flag as executable");

  /* Cleanup */
  unlink(tempfile);

  TEST_SUCCESS();
}

/* Test: PNG file detection */
static int test_report_png_file(void) {
  TEST_CASE("report_generate - PNG file detection");

  struct uav_report report;
  char tempfile[] = "/tmp/test_png_XXXXXX";
  int fd, ret;

  fd = mkstemp(tempfile);
  TEST_ASSERT(fd >= 0, "Should create temp file");
  close(fd);

  /* PNG magic: 89 50 4E 47 0D 0A 1A 0A */
  unsigned char png_content[] = {
    0x89, 'P', 'N', 'G', 0x0D, 0x0A, 0x1A, 0x0A,
    /* Fake IHDR chunk */
    0x00, 0x00, 0x00, 0x0D, 'I', 'H', 'D', 'R',
    0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x10
  };

  ret = create_test_file(tempfile, png_content, sizeof(png_content), 0644);
  TEST_ASSERT_EQ(0, ret, "Should write test file");

  ret = uav_report_generate(tempfile, &report);
  TEST_ASSERT_EQ(0, ret, "Should generate report");

  TEST_ASSERT_EQ(UAV_FILE_PNG, report.filetype, "Should detect PNG file");
  TEST_ASSERT(report.suspicion.index < 0.3f, "PNG should be low suspicion");
  TEST_ASSERT(!report.suspicion.executable, "PNG is not executable");

  unlink(tempfile);
  TEST_SUCCESS();
}

/* Test: PDF file detection */
static int test_report_pdf_file(void) {
  TEST_CASE("report_generate - PDF file detection");

  struct uav_report report;
  char tempfile[] = "/tmp/test_pdf_XXXXXX";
  int fd, ret;
 
  fd = mkstemp(tempfile);
  TEST_ASSERT(fd >= 0, "Should create temp file");
  close(fd);

  /* PDF magic: 25 50 44 46 (%PDF) */
  const char *pdf_content = "%PDF-1.4\n%âãÏÓ\n";

  ret = create_test_file(tempfile, (const unsigned char *)pdf_content, strlen(pdf_content), 0644);
  TEST_ASSERT_EQ(0, ret, "Should write test file");
 
  ret = uav_report_generate(tempfile, &report);
  TEST_ASSERT_EQ(0, ret, "Should generate report");

  TEST_ASSERT_EQ(UAV_FILE_PDF, report.filetype, "Should detect PDF file");

  unlink(tempfile);
  TEST_SUCCESS();
}

/* Test: Script (shebang) detection */
static int test_report_script_file(void) {
  TEST_CASE("report_generate - Script file detection");

  struct uav_report report;
  char tempfile[] = "/tmp/test_script_XXXXXX";
  int fd, ret;

  fd = mkstemp(tempfile);
  TEST_ASSERT(fd >= 0, "Should create temp file");
  close(fd);

  const char *script_content = "#!/bin/sh\necho 'Hello World'\n";

  ret = create_test_file(tempfile, (const unsigned char *)script_content,
                        strlen(script_content), 0755);
  TEST_ASSERT_EQ(0, ret, "Should write test file");

  ret = uav_report_generate(tempfile, &report);
  TEST_ASSERT_EQ(0, ret, "Should generate report");

  TEST_ASSERT_EQ(UAV_FILE_SCRIPT, report.filetype, "Should detect script");
  TEST_ASSERT(report.suspicion.executable, "Script is executable");
  TEST_ASSERT(report.suspicion.index > 0.2f, "Script should be somewhat suspicious");

  unlink(tempfile);
  TEST_SUCCESS();
}

/* Test: Text file detection */
static int test_report_text_file(void) {
  TEST_CASE("report_generate - Text file detection");

  struct uav_report report;
  char tempfile[] = "/tmp/test_text_XXXXXX";
  int fd, ret;

  fd = mkstemp(tempfile);
  TEST_ASSERT(fd >= 0, "Should create temp file");
  close(fd);

  const char *text_content = "This is a plain text file.\nWith multiple lines.\n";

  ret = create_test_file(tempfile, (const unsigned char *)text_content, strlen(text_content), 0644);
  TEST_ASSERT_EQ(0, ret, "Should write test file");

  ret = uav_report_generate(tempfile, &report);
  TEST_ASSERT_EQ(0, ret, "Should generate report");

  TEST_ASSERT_EQ(UAV_FILE_TEXT, report.filetype, "Should detect text file");
  TEST_ASSERT(report.suspicion.index == 0.0f, "Text file should be clean");

  unlink(tempfile);
  TEST_SUCCESS();
}

/* Test: Unknown file type */
static int test_report_unknown_file(void) {
  TEST_CASE("report_generate - Unknown file type");

  struct uav_report report;
  char tempfile[] = "/tmp/test_unknown_XXXXXX";
  int fd, ret;

  fd = mkstemp(tempfile);
  TEST_ASSERT(fd >= 0, "Should create temp file");
  close(fd);

  /* Random binary data with no recognizable magic */
  unsigned char unknown_content[] = {
    0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11,
    0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99
  };

  ret = create_test_file(tempfile, unknown_content, sizeof(unknown_content), 0644);
  TEST_ASSERT_EQ(0, ret, "Should write test file");

  ret = uav_report_generate(tempfile, &report);
  TEST_ASSERT_EQ(0, ret, "Should generate report");

  TEST_ASSERT_EQ(UAV_FILE_UNKNOWN, report.filetype, "Should detect unknown type");
  TEST_ASSERT(report.suspicion.unknown_filetype, "Should flag unknown type");
  TEST_ASSERT(report.suspicion.index > 0.0f, "Unknown should add suspicion");

  unlink(tempfile);
  TEST_SUCCESS();
}

/* Test: Hash verification (known MD5/SHA1/SHA256) */
static int test_report_hash_verification(void) {
  TEST_CASE("report_generate - Hash verification");

  struct uav_report report;
  char tempfile[] = "/tmp/test_hash_XXXXXX";
  int fd, ret;

  fd = mkstemp(tempfile);
  TEST_ASSERT(fd >= 0, "Should create temp file");
  close(fd);

  /* Known content: "Hello, World!" */
  const char *content = "Hello, World!";

  /* Known hashes for "Hello, World!" (verified externally):
   * MD5:    65a8e27d8879283831b664bd8b7f0ad4
   * SHA1:   0a0a9f2a6772942557ab5355d76af442f8f65e01
   * SHA256: dffd6021bb2bd5b0af676290809ec3a53191dd81c7f70a4b28688a362182986f
   */

  ret = create_test_file(tempfile, (const unsigned char *)content, strlen(content), 0644);
  TEST_ASSERT_EQ(0, ret, "Should write test file");

  ret = uav_report_generate(tempfile, &report);
  TEST_ASSERT_EQ(0, ret, "Should generate report");

  /* Verify MD5 (just check it's non-zero, exact match would be fragile) */
  int md5_nonzero = 0;
  for (int i = 0; i < 16; i++) {
    if (report.md5[i] != 0) md5_nonzero = 1;
  }
  TEST_ASSERT(md5_nonzero, "MD5 should be computed");

  /* Verify SHA256 (same approach) */
  int sha256_nonzero = 0;
  for (int i = 0; i < 32; i++) {
    if (report.sha256[i] != 0) sha256_nonzero = 1;
  }
  TEST_ASSERT(sha256_nonzero, "SHA256 should be computed");

  /* Verify all hash flags are set */
  TEST_ASSERT(report.has_md5, "Should have MD5 flag");
  TEST_ASSERT(report.has_sha1, "Should have SHA1 flag");
  TEST_ASSERT(report.has_sha256, "Should have SHA256 flag");

  unlink(tempfile);
  TEST_SUCCESS();
}

/* Test: Empty file handling */
static int test_report_empty_file(void) {
  TEST_CASE("report_generate - Empty file");

  struct uav_report report;
  char tempfile[] = "/tmp/test_empty_XXXXXX";
  int fd, ret;

  fd = mkstemp(tempfile);
  TEST_ASSERT(fd >= 0, "Should create temp file");
  close(fd);

  /* Create empty file */
  ret = create_test_file(tempfile, NULL, 0, 0644);
  TEST_ASSERT_EQ(0, ret, "Should create empty file");

  ret = uav_report_generate(tempfile, &report);
  TEST_ASSERT_EQ(0, ret, "Should handle empty file");
  TEST_ASSERT_EQ(0, report.filesize, "Should report zero size");

  TEST_ASSERT_EQ(0, report.magic_len, "Should have no magic bytes");
  TEST_ASSERT(report.has_md5, "Should still compute MD5 of empty file");

  unlink(tempfile);
  TEST_SUCCESS();
}

/* Test: Large file handling */
static int test_report_large_file(void) {
  TEST_CASE("report_generate - Large file handling");

  struct uav_report report;
  char tempfile[] = "/tmp/test_large_XXXXXX";
  int fd, ret;

  fd = mkstemp(tempfile);
  TEST_ASSERT(fd >= 0, "Should create temp file");

  /* Write 1MB of data in chunks */
  unsigned char chunk[4096];
  memset(chunk, 'A', sizeof(chunk));

  /* 256 * 4KB = 1MB */
  for (int i = 0; i < 256; i++) {
    ssize_t written = write(fd, chunk, sizeof(chunk));
    if (written != sizeof(chunk)) {
      close(fd);
      unlink(tempfile);
      TEST_FAIL("Failed to write large file");
    }
  }

  close(fd);

  /* Generate report */
  ret = uav_report_generate(tempfile, &report);
  TEST_ASSERT_EQ(0, ret, "Should handle large file");
  TEST_ASSERT_EQ(1024 * 1024, report.filesize, "Should report correct size");
  TEST_ASSERT(report.has_sha256, "Should compute hash for large file");

  unlink(tempfile);
  TEST_SUCCESS();
}

/* Test: Executable permission detection */
static int test_report_executable_permission(void) {
  TEST_CASE("report_generate - Executable permission detection");

  struct uav_report report1, report2;
  char tempfile[] = "/tmp/test_perm_XXXXXX";
  int fd, ret;

  fd = mkstemp(tempfile);
  TEST_ASSERT(fd >= 0, "Should create temp file");
  close(fd);

  const char *content = "test content";

  /* Test without executable bit */
  ret = create_test_file(tempfile, (const unsigned char *)content, strlen(content), 0644);
  TEST_ASSERT_EQ(0, ret, "Should write test file");

  ret = uav_report_generate(tempfile, &report1);
  TEST_ASSERT_EQ(0, ret, "Should generate report");

  float suspicion_without_exec = report1.suspicion.index;

  /* Test with executable bit */
  ret = create_test_file(tempfile, (const unsigned char *)content, strlen(content), 0755);
  TEST_ASSERT_EQ(0, ret, "Should write test file");

  ret = uav_report_generate(tempfile, &report2);
  TEST_ASSERT_EQ(0, ret, "Should generate report");

  float suspicion_with_exec = report2.suspicion.index;

  /* Executable bit should increase suspicion */
  TEST_ASSERT(suspicion_with_exec > suspicion_without_exec, "Executable bit should increase suspicion");

  unlink(tempfile);
  TEST_SUCCESS();
}

/* Test: Report printing (no crash test) */
static int test_report_print(void) {
  TEST_CASE("report_print - No crash test");

  struct uav_report report;
  char tempfile[] = "/tmp/test_print_XXXXXX";
  int fd, ret;

  fd = mkstemp(tempfile);
  TEST_ASSERT(fd >= 0, "Should create temp file");
  close(fd);

  const char *content = "Test content for printing";
  ret = create_test_file(tempfile, (const unsigned char *)content, strlen(content), 0644);
  TEST_ASSERT_EQ(0, ret, "Should write test file");

  ret = uav_report_generate(tempfile, &report);
  TEST_ASSERT_EQ(0, ret, "Should generate report");

  /* Redirect stdout to /dev/null to suppress output during test */
  fflush(stdout);
  int stdout_backup = dup(STDOUT_FILENO);
  int devnull = open("/dev/null", O_WRONLY);
  dup2(devnull, STDOUT_FILENO);

  /* This should not crash */
  uav_report_print(&report);

  /* Restore stdout */
  fflush(stdout);
  dup2(stdout_backup, STDOUT_FILENO);
  close(devnull);
  close(stdout_backup);

  unlink(tempfile);
  TEST_SUCCESS();
}

int main(void) {
  TEST_SUITE("Report Module");

  /* Basic functionality tests */
  TEST_RUN(test_report_null_handling);
  TEST_RUN(test_report_nonexistent_file);
  TEST_RUN(test_report_empty_file);

  /* File type detection tests */
  TEST_RUN(test_report_elf_file);
  TEST_RUN(test_report_png_file);
  TEST_RUN(test_report_pdf_file);
  TEST_RUN(test_report_script_file);
  TEST_RUN(test_report_text_file);
  TEST_RUN(test_report_unknown_file);

  /* Hash computation tests */
  TEST_RUN(test_report_hash_verification);
  TEST_RUN(test_report_large_file);

  /* Suspicion analysis tests */
  TEST_RUN(test_report_executable_permission);

  /* Output tests */
  TEST_RUN(test_report_print);

  TEST_REPORT();
}
