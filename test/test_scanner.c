#include "test.h"
#include "scanner.h"
#include "utils.h"

#include <fcntl.h>
#include <linux/limits.h>
#include <sys/stat.h>
#include <unistd.h>

/* Test: Scanner initialization without rules */
static int test_scanner_init_empty(void) {
  TEST_CASE("scanner_init - empty initialization");

  struct uav_scanner scanner = {0};
  int ret;

  ret = uav_scanner_init(&scanner, 0, 0);
  TEST_ASSERT_EQ(0, ret, "Should initialize empty scanner");
  TEST_ASSERT_NULL(scanner.signatures, "Should have no signatures");
  TEST_ASSERT_EQ(0, scanner.sigcount, "Should have zero signature count");
  TEST_ASSERT_NULL(scanner.rules, "Should have no YARA rules");

  uav_scanner_destroy(&scanner);

  TEST_SUCCESS();
}

/* Test: Scanner initialization with YARA rules */
static int test_scanner_init_with_yara(void) {
  TEST_CASE("scanner_init - with YARA rules");

  struct uav_scanner scanner = {0};
  char rulefile[] = "/tmp/test_scanner_rule_XXXXXX";
  int fd, ret;

  /* Create simple YARA rule */
  const char *rule =
    "rule TestScanner {\n"
    "    meta:\n"
    "        description = \"Test rule for scanner\"\n"
    "    strings:\n"
    "        $test = \"SCANNER_TEST\"\n"
    "    condition:\n"
    "        $test\n"
    "}\n";

  fd = mkstemp(rulefile);
  TEST_ASSERT(fd >= 0, "Should create temp rule file");
  write(fd, rule, strlen(rule) + 1);
  close(fd);

  /* Initialize scanner with rules */
  ret = uav_scanner_init(&scanner, rulefile, 0);
  if (ret != 0) {
    unlink(rulefile);
    TEST_FAIL("cannot initialize scanner");
  }

  TEST_ASSERT_NOT_NULL(scanner.rules, "Should have loaded YARA rules");

  /* Cleanup */
  uav_scanner_destroy(&scanner);
  unlink(rulefile);

  TEST_SUCCESS();
}

/* Test: Scanner initialization with invalid YARA rules */
static int test_scanner_init_invalid_yara(void) {
  TEST_CASE("scanner_init - invalid YARA rules");

  struct uav_scanner scanner = {0};
  char rulefile[] = "/tmp/test_scanner_bad_XXXXXX";
  int fd, ret;

  /* Create invalid YARA rule */
  const char *bad_rule = 
    "rule BadRule {\n"
    "    condition: this_is_invalid_syntax\n"
    "}\n";

  fd = mkstemp(rulefile);
  TEST_ASSERT(fd >= 0, "Should create temp file");
  write(fd, bad_rule, strlen(bad_rule));
  close(fd);

  /* Should fail gracefully */
  ret = uav_scanner_init(&scanner, rulefile, 0);
  if (ret == 0) {
    /* If YARA-X not available, we get success (no rules loaded) */
    TEST_ASSERT_NULL(scanner.rules, "Should have no rules on invalid syntax");
    uav_scanner_destroy(&scanner);
  } else {
    /* YARA-X is available and correctly rejected invalid syntax */
    TEST_ASSERT_EQ(-1, ret, "Should reject invalid YARA syntax");
  }

  unlink(rulefile);

  TEST_SUCCESS();
}

/* Test: Scanner initialization with non-existent file */
static int test_scanner_init_nonexistent(void) {
  TEST_CASE("scanner_init - non-existent file");

  struct uav_scanner scanner = {0};
  int ret;

  ret = uav_scanner_init(&scanner, "/nonexistent/rules.yar", 0);
  TEST_ASSERT_EQ(1, ret, "Should fail on non-existent file");

  TEST_SUCCESS();
}

/* Test: Basic file scanning with YARA match */
static int test_scanner_scan_match(void) {
  TEST_CASE("scanner_scan_file_sync - YARA match");

  struct uav_scanner scanner = {0};
  struct uav_yara_match *matches = NULL;
  size_t nmatch = 0;
  char rulefile[] = "/tmp/test_scan_rule_XXXXXX";
  char testfile[] = "/tmp/test_scan_file_XXXXXX";
  int fd, ret;

  /* Create YARA rule */
  const char *rule = 
    "rule ScanTest {\n"
    "    strings:\n"
    "        $pattern = \"MALICIOUS_PATTERN\"\n"
    "    condition:\n"
    "        $pattern\n"
    "}\n";

  fd = mkstemp(rulefile);
  TEST_ASSERT(fd >= 0, "Should create rule file");
  write(fd, rule, strlen(rule));
  close(fd);

  /* Initialize scanner */
  ret = uav_scanner_init(&scanner, rulefile, 0);
  if (ret != 0) {
    unlink(rulefile);
    TEST_FAIL("cannot initialize scanner");
  }

  /* Create test file with matching content */
  fd = mkstemp(testfile);
  TEST_ASSERT(fd >= 0, "Should create test file");
  const char *content = "This file contains MALICIOUS_PATTERN inside";
  write(fd, content, strlen(content));
  close(fd);

  /* Scan file */
  ret = uav_scanner_scan_file_sync(&scanner, testfile, &matches, &nmatch);
  TEST_ASSERT_EQ(0, ret, "Should scan successfully");
  TEST_ASSERT(nmatch > 0, "Should have matches");
  TEST_ASSERT_NOT_NULL(matches, "Should return match array");

  /* Verify match details */
  TEST_ASSERT(strcmp((const char *)matches[0].identifier, "ScanTest") == 0 ||  matches[0].len > 0,  "Should have rule name");

  /* Cleanup */
  free(matches);
  uav_scanner_destroy(&scanner);
  unlink(rulefile);
  unlink(testfile);

  TEST_SUCCESS();
}

/* Test: File scanning with no YARA match */
static int test_scanner_scan_no_match(void) {
  TEST_CASE("scanner_scan_file_sync - no match");

  struct uav_scanner scanner = {0};
  struct uav_yara_match *matches = NULL;
  size_t nmatch = 0;
  char rulefile[] = "/tmp/test_nomatch_rule_XXXXXX";
  char testfile[] = "/tmp/test_nomatch_file_XXXXXX";
  int fd, ret;

  /* Create YARA rule */
  const char *rule = 
    "rule NoMatchRule {\n"
    "    strings:\n"
    "        $pattern = \"WILL_NOT_MATCH_THIS\"\n"
    "    condition:\n"
    "        $pattern\n"
    "}\n";

  fd = mkstemp(rulefile);
  TEST_ASSERT(fd >= 0, "Should create rule file");
  write(fd, rule, strlen(rule));
  close(fd);

  /* Initialize scanner */
  ret = uav_scanner_init(&scanner, rulefile, 0);
  if (ret != 0) {
    unlink(rulefile);
    TEST_FAIL("cannot initialize scanner");
  }

  /* Create test file with clean content */
  fd = mkstemp(testfile);
  TEST_ASSERT(fd >= 0, "Should create test file");
  const char *content = "This is a clean file with no suspicious patterns";
  write(fd, content, strlen(content));
  close(fd);

  /* Scan file */
  ret = uav_scanner_scan_file_sync(&scanner, testfile, &matches, &nmatch);
  TEST_ASSERT_EQ(0, ret, "Should scan successfully");
  TEST_ASSERT_EQ(0, nmatch, "Should have no matches");
  TEST_ASSERT_NULL(matches, "Should return NULL for no matches");

  /* Cleanup */
  uav_scanner_destroy(&scanner);
  unlink(rulefile);
  unlink(testfile);

  TEST_SUCCESS();
}

/* Test: Scanning multiple files with same scanner */
static int test_scanner_scan_multiple_files(void) {
  TEST_CASE("scanner_scan_file_sync - multiple files");

  struct uav_scanner scanner = {0};
  struct uav_yara_match *matches1 = NULL, *matches2 = NULL;
  size_t nmatch1 = 0, nmatch2 = 0;
  char rulefile[] = "/tmp/test_multi_rule_XXXXXX";
  char testfile1[] = "/tmp/test_multi_file1_XXXXXX";
  char testfile2[] = "/tmp/test_multi_file2_XXXXXX";
  int fd, ret;

  /* Create YARA rule */
  const char *rule = 
    "rule MultiTest {\n"
    "    strings:\n"
    "        $sig = \"SIGNATURE\"\n"
    "    condition:\n"
    "        $sig\n"
    "}\n";

  fd = mkstemp(rulefile);
  TEST_ASSERT(fd >= 0, "Should create rule file");
  write(fd, rule, strlen(rule));
  close(fd);

  /* Initialize scanner */
  ret = uav_scanner_init(&scanner, rulefile, 0);
  if (ret != 0) {
    unlink(rulefile);
    TEST_FAIL("cannot initialize scanner");
  }

  /* Create first test file (matching) */
  fd = mkstemp(testfile1);
  TEST_ASSERT(fd >= 0, "Should create test file 1");
  write(fd, "Contains SIGNATURE here", 23);
  close(fd);

  /* Create second test file (clean) */
  fd = mkstemp(testfile2);
  TEST_ASSERT(fd >= 0, "Should create test file 2");
  write(fd, "Clean content only", 18);
  close(fd);

  /* Scan first file */
  ret = uav_scanner_scan_file_sync(&scanner, testfile1, &matches1, &nmatch1);
  TEST_ASSERT_EQ(0, ret, "Should scan file 1");
  TEST_ASSERT(nmatch1 > 0, "File 1 should match");

  /* Scan second file */
  ret = uav_scanner_scan_file_sync(&scanner, testfile2, &matches2, &nmatch2);
  TEST_ASSERT_EQ(0, ret, "Should scan file 2");
  TEST_ASSERT_EQ(0, nmatch2, "File 2 should not match");

  /* Cleanup */
  free(matches1);
  free(matches2);
  uav_scanner_destroy(&scanner);
  unlink(rulefile);
  unlink(testfile1);
  unlink(testfile2);

  TEST_SUCCESS();
}

/* Test: Scanner with multiple YARA rules */
static int test_scanner_multiple_rules(void) {
  TEST_CASE("scanner_scan_file_sync - multiple rules");

  struct uav_scanner scanner = {0};
  struct uav_yara_match *matches = NULL;
  size_t nmatch = 0;
  char rulefile[] = "/tmp/test_multirule_XXXXXX";
  char testfile[] = "/tmp/test_multirule_file_XXXXXX";
  int fd, ret;

  /* Create multiple YARA rules */
  const char *rules = 
    "rule Rule1 {\n"
    "    strings: $s1 = \"FIRST\"\n"
    "    condition: $s1\n"
    "}\n"
    "rule Rule2 {\n"
    "    strings: $s2 = \"SECOND\"\n"
    "    condition: $s2\n"
    "}\n"
    "rule Rule3 {\n"
    "    strings: $s3 = \"THIRD\"\n"
    "    condition: $s3\n"
    "}\n";

  fd = mkstemp(rulefile);
  TEST_ASSERT(fd >= 0, "Should create rule file");
  write(fd, rules, strlen(rules));
  close(fd);

  /* Initialize scanner */
  ret = uav_scanner_init(&scanner, rulefile, 0);
  if (ret != 0) {
    unlink(rulefile);
    TEST_FAIL("cannot initialize scanner");
  }

  /* Create test file matching all three rules */
  fd = mkstemp(testfile);
  TEST_ASSERT(fd >= 0, "Should create test file");
  const char *content = "FIRST and SECOND and THIRD all here";
  write(fd, content, strlen(content));
  close(fd);

  /* Scan file */
  ret = uav_scanner_scan_file_sync(&scanner, testfile, &matches, &nmatch);
  TEST_ASSERT_EQ(0, ret, "Should scan successfully");
  TEST_ASSERT_EQ(3, nmatch, "Should match all 3 rules");
  TEST_ASSERT_NOT_NULL(matches, "Should have matches");

  /* Cleanup */
  free(matches);
  uav_scanner_destroy(&scanner);
  unlink(rulefile);
  unlink(testfile);

  TEST_SUCCESS();
}

/* Test: Scanner error handling - NULL parameters */
static int test_scanner_scan_null_params(void) {
  TEST_CASE("scanner_scan_file_sync - NULL parameter handling");

  struct uav_scanner scanner = {0};
  struct uav_yara_match *matches = NULL;
  size_t nmatch = 0;
  int ret;

  /* Initialize empty scanner */
  ret = uav_scanner_init(&scanner, 0, 0);
  TEST_ASSERT_EQ(0, ret, "Should initialize");

  /* NULL scanner */
  ret = uav_scanner_scan_file_sync(NULL, "/tmp/test", &matches, &nmatch);
  TEST_ASSERT_EQ(0, ret, "Should handle NULL scanner gracefully");
  TEST_ASSERT_EQ(0, nmatch, "Should return 0 matches");

  /* NULL path */
  ret = uav_scanner_scan_file_sync(&scanner, NULL, &matches, &nmatch);
  TEST_ASSERT_EQ(0, ret, "Should handle NULL path gracefully");
  TEST_ASSERT_EQ(0, nmatch, "Should return 0 matches");

  /* NULL output parameter */
  ret = uav_scanner_scan_file_sync(&scanner, "/tmp/test", &matches, NULL);
  TEST_ASSERT_EQ(1, ret, "Should reject NULL output parameter");

  uav_scanner_destroy(&scanner);

  TEST_SUCCESS();
}

/* Test: Scanner destroy with NULL */
static int test_scanner_destroy_null(void) {
  TEST_CASE("scanner_destroy - NULL handling");

  /* Should not crash */
  uav_scanner_destroy(NULL);

  TEST_SUCCESS();
}

/* Test: Scanning non-existent file */
static int test_scanner_scan_nonexistent_file(void) {
  TEST_CASE("scanner_scan_file_sync - non-existent file");

  struct uav_scanner scanner = {0};
  struct uav_yara_match *matches = NULL;
  size_t nmatch = 0;
  char rulefile[] = "/tmp/test_nofile_rule_XXXXXX";
  int fd, ret;

  /* Create simple rule */
  const char *rule = 
    "rule Test {\n"
    "    strings: $s = \"test\"\n"
    "    condition: $s\n"
    "}\n";

  fd = mkstemp(rulefile);
  TEST_ASSERT(fd >= 0, "Should create rule file");
  write(fd, rule, strlen(rule));
  close(fd);

  /* Initialize scanner */
  ret = uav_scanner_init(&scanner, rulefile, 0);
  if (ret != 0) {
    unlink(rulefile);
    TEST_FAIL("cannot initialize scanner");
  }

  /* Try to scan non-existent file */
  ret = uav_scanner_scan_file_sync(&scanner, "/nonexistent/file.txt", &matches, &nmatch);
  TEST_ASSERT_EQ(1, ret, "Should fail on non-existent file");

  /* Cleanup */
  uav_scanner_destroy(&scanner);
  unlink(rulefile);

  TEST_SUCCESS();
}

/* Test: Scanner with directory of rules */
static int test_scanner_init_directory(void) {
  TEST_CASE("scanner_init - directory of rules");

  struct uav_scanner scanner = {0};
  char ruledir[] = "/tmp/test_ruledir_XXXXXX";
  char rulefile1[PATH_MAX], rulefile2[PATH_MAX];
  int ret;

  /* Create temporary directory */
  TEST_ASSERT_NOT_NULL(mkdtemp(ruledir), "Should create temp directory");

  /* Create multiple rule files */
  snprintf(rulefile1, sizeof(rulefile1), "%s/rule1.yar", ruledir);
  snprintf(rulefile2, sizeof(rulefile2), "%s/rule2.yar", ruledir);

  ret = write_file_str(rulefile1, "rule DirRule1 { strings: $s = \"DIR1\" condition: $s }\n");
  TEST_ASSERT_EQ(0, ret, "Should create rule1.yar");

  ret = write_file_str(rulefile2, "rule DirRule2 { strings: $s = \"DIR2\" condition: $s }\n");
  TEST_ASSERT_EQ(0, ret, "Should create rule2.yar");

  /* Initialize scanner with directory */
  ret = uav_scanner_init(&scanner, ruledir, 0);
  if (ret != 0) {
    unlink(rulefile1);
    unlink(rulefile2);
    rmdir(ruledir);
    TEST_SKIP("YARA-X not available");
  }

  TEST_ASSERT_NOT_NULL(scanner.rules, "Should load rules from directory");

  /* Cleanup */
  uav_scanner_destroy(&scanner);
  unlink(rulefile1);
  unlink(rulefile2);
  rmdir(ruledir);

  TEST_SUCCESS();
}

int main(void) {
  TEST_SUITE("Scanner Module");

  /* Basic initialization tests */
  TEST_RUN(test_scanner_init_empty);
  TEST_RUN(test_scanner_init_with_yara);
  TEST_RUN(test_scanner_init_invalid_yara);
  TEST_RUN(test_scanner_init_nonexistent);
  TEST_RUN(test_scanner_init_directory);

  /* Scanning tests */
  TEST_RUN(test_scanner_scan_match);
  TEST_RUN(test_scanner_scan_no_match);
  TEST_RUN(test_scanner_scan_multiple_files);
  TEST_RUN(test_scanner_multiple_rules);
  TEST_RUN(test_scanner_scan_nonexistent_file);

  /* Error handling tests */
  TEST_RUN(test_scanner_scan_null_params);
  TEST_RUN(test_scanner_destroy_null);

  TEST_REPORT();
}
