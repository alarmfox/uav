#include "test.h"
#include "utils.h"

int test_safe_strcpy_normal(void) {
  TEST_CASE("safe_strcpy - normal copy");

  char buf[20];
  safe_strcpy(buf, "hello", sizeof(buf));

  TEST_ASSERT_EQ(0, strcmp(buf, "hello"), "Should copy correctly");
  TEST_SUCCESS();
}

int test_safe_strcpy_truncate(void) {
  TEST_CASE("safe_strcpy - truncation");

  char buf[5];
  safe_strcpy(buf, "hello world", sizeof(buf));

  TEST_ASSERT_EQ(4, strlen(buf), "Should truncate to size-1");
  TEST_ASSERT(buf[4] == '\0', "Should null-terminate");
  TEST_SUCCESS();
}

int test_safe_strcpy_edge_cases(void) {
  TEST_CASE("safe_strcpy - edge cases");

  char buf[10] = "garbage";

  // NULL src
  safe_strcpy(buf, NULL, sizeof(buf));
  TEST_ASSERT_EQ(0, strcmp(buf, "garbage"), "Should not modify on NULL src");

  // NULL dst
  safe_strcpy(NULL, "hello", 10);  // Should not crash

  // size = 0
  safe_strcpy(buf, "hello", 0);  // Should not crash

  TEST_SUCCESS();
}

int test_digest_to_hex(void) {
  TEST_CASE("digest_to_hex");

  unsigned char digest[] = {0xde, 0xad, 0xbe, 0xef};
  char hex[9];

  ssize_t len = digest_to_hex(digest, 4, hex);
  hex[len] = '\0';

  TEST_ASSERT_EQ(8, len, "Should return correct length");
  TEST_ASSERT_EQ(0, strcmp(hex, "deadbeef"), "Should convert correctly");

  TEST_SUCCESS();
}

int test_digest_roundtrip(void) {
  TEST_CASE("digest hex roundtrip");

  unsigned char original[] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef};
  char hex[17];
  unsigned char decoded[8];

  digest_to_hex(original, 8, hex);
  hex[16] = '\0';

  digest_from_hex(hex, 16, decoded);

  TEST_ASSERT_EQ(0, memcmp(original, decoded, 8), "Roundtrip should match");

  TEST_SUCCESS();
}

int main(void) {
  TEST_SUITE("Utils Module");

  RUN_TEST(test_safe_strcpy_normal);
  RUN_TEST(test_safe_strcpy_truncate);
  RUN_TEST(test_safe_strcpy_edge_cases);
  RUN_TEST(test_digest_to_hex);
  RUN_TEST(test_digest_roundtrip);

  TEST_REPORT();
}
