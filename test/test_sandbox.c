#include "sandbox.h"
#include "uav_test.h"
#include "utils.h"

static const char program[] = "#/bin/sh\nexit 0\n";

TEST(test_run_sandbox_ns) {
  char path[] = "/tmp/uav_sandbox_test_XXXXXX";
  int fd;
  struct uav_sandbox s;
  int ret = -1;

  fd = mkstemp(path);
  TEST_ASSERT(fd >= 0);

  ret = uav_write_all(fd, program, strlen(program) + 1);
  TEST_ASSERT_EQ(ret, 0);

  ret = uav_sandbox_create(&s, UAV_SANDBOX_BACKEND_NS);
  TEST_ASSERT_EQ(ret, 0);

  ret = uav_sandbox_run_program(&s, path);
  TEST_ASSERT_EQ(ret, 0);

  ret = uav_sandbox_destroy(&s);
  TEST_ASSERT_EQ(ret, 0);

  return ret;
}

int main (void) {

  TEST_SUITE("Sandbox");

  RUN_TEST(test_run_sandbox_ns);

  return uav_test_report();
}
