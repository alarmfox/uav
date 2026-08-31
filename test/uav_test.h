#ifndef UAV_TEST_H
#define UAV_TEST_H

#include <inttypes.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef UAV_TEST_NO_COLOR
#define UAV_RED   "\x1b[31m"
#define UAV_GREEN "\x1b[32m"
#define UAV_BLUE  "\x1b[34m"
#define UAV_RESET "\x1b[0m"
#else
#define UAV_RED   ""
#define UAV_GREEN ""
#define UAV_BLUE  ""
#define UAV_RESET ""
#endif

struct uav_test_statistics {
  unsigned total;
  unsigned passed;
  unsigned failed;
};

static struct uav_test_statistics uav_test_stats;

#define TEST(name) static int name(void)

#define TEST_SUITE(name)                                        \
  do {                                                          \
    printf("\n" UAV_BLUE "=== %s ===" UAV_RESET "\n", (name));  \
  } while (0)

#define TEST_FAIL(message)                                      \
  do {                                                          \
    printf("    %s:%d: %s\n", __FILE__, __LINE__, (message));   \
    return 1;                                                   \
  } while (0)

#define TEST_ASSERT(condition)                                  \
  do {                                                          \
    if (!(condition)) {                                         \
      printf("    %s:%d: assertion failed: %s\n",               \
          __FILE__, __LINE__, #condition);                      \
      return 1;                                                 \
    }                                                           \
  } while (0)

#define TEST_ASSERT_MSG(condition, message)                     \
  do {                                                          \
    if (!(condition)) {                                         \
      printf("    %s:%d: assertion failed: %s: %s\n",           \
          __FILE__, __LINE__, #condition, (message));           \
      return 1;                                                 \
    }                                                           \
  } while (0)

#define TEST_ASSERT_EQ(expected, actual)                        \
  do {                                                          \
    intmax_t uav_expected_ = (intmax_t)(expected);              \
    intmax_t uav_actual_ = (intmax_t)(actual);                  \
    if (uav_expected_ != uav_actual_) {                         \
      printf("    %s:%d: expected %" PRIdMAX                    \
          ", got %" PRIdMAX "\n",                               \
          __FILE__, __LINE__, uav_expected_, uav_actual_);      \
      return 1;                                                 \
    }                                                           \
  } while (0)

#define TEST_ASSERT_PTR_EQ(expected, actual)                    \
  do {                                                          \
    const void *uav_expected_ = (expected);                     \
    const void *uav_actual_ = (actual);                         \
    if (uav_expected_ != uav_actual_) {                         \
      printf("    %s:%d: expected %p, got %p\n",                \
          __FILE__, __LINE__, uav_expected_, uav_actual_);      \
      return 1;                                                 \
    }                                                           \
  } while (0)

#define TEST_ASSERT_NULL(pointer)                               \
  TEST_ASSERT_PTR_EQ(NULL, (pointer))

#define TEST_ASSERT_NOT_NULL(pointer)                           \
  TEST_ASSERT((pointer) != NULL)

#define TEST_ASSERT_STR_EQ(expected, actual)                    \
  do {                                                          \
    const char *uav_expected_ = (expected);                     \
    const char *uav_actual_ = (actual);                         \
    if (uav_expected_ == NULL || uav_actual_ == NULL ||         \
        strcmp(uav_expected_, uav_actual_) != 0) {              \
      printf("    %s:%d: expected \"%s\", got \"%s\"\n",        \
          __FILE__, __LINE__,                                   \
          uav_expected_ ? uav_expected_ : "(null)",             \
          uav_actual_ ? uav_actual_ : "(null)");                \
      return 1;                                                 \
    }                                                           \
  } while (0)

#define RUN_TEST(function)                                      \
  do {                                                          \
    int uav_result_;                                            \
    uav_test_stats.total++;                                     \
    uav_result_ = (function)();                                 \
    if (uav_result_ == 0) {                                     \
      uav_test_stats.passed++;                                  \
      printf(UAV_GREEN "PASS" UAV_RESET " %s\n", #function);    \
    } else {                                                    \
      uav_test_stats.failed++;                                  \
      printf(UAV_RED "FAIL" UAV_RESET " %s\n", #function);      \
    }                                                           \
  } while (0)

static int uav_test_report(void) {
  printf("\n" UAV_BLUE "=== Summary ===" UAV_RESET "\n");
  printf("Total:  %u\n", uav_test_stats.total);
  printf(UAV_GREEN "Passed: %u" UAV_RESET "\n",
      uav_test_stats.passed);
  printf(UAV_RED "Failed: %u" UAV_RESET "\n",
      uav_test_stats.failed);

  return uav_test_stats.failed == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}

#endif
