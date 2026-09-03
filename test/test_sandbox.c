#include <errno.h>

#include "agent_protocol.h"
#include "sandbox.h"
#include "uav_test.h"
#include "utils.h"

static const char program[] = "#!/bin/sh\necho hello-world\nexit 0\n";

TEST(test_run_sandbox_ns) {
  char path[] = "/tmp/uav_sandbox_test_XXXXXX";
  int fd;
  struct uav_sandbox s;
  int destroy_ret;
  int run_ret;
  int ret = -1;
  static const char* const argv[] = {"sandbox-test", NULL};
  struct uav_agent_exec_params params = {
      .flags = 0,
      .argc = 1,
      .argv = argv,
      .envc = 0,
      .envp = NULL,
  };

  fd = mkstemp(path);
  TEST_ASSERT(fd >= 0);

  ret = uav_write_all(fd, program, strlen(program) + 1);
  TEST_ASSERT_EQ(0, ret);
  TEST_ASSERT_EQ(0, close(fd));

  ret = uav_sandbox_create(&s, UAV_SANDBOX_BACKEND_CONTAINER);
  TEST_ASSERT_EQ(0, ret);

  run_ret = uav_sandbox_run_program(&s, path, &params);
  destroy_ret = uav_sandbox_destroy(&s);
  unlink(path);

  TEST_ASSERT_EQ(0, destroy_ret);
  TEST_ASSERT_EQ(0, run_ret);

  return 0;
}

TEST(test_run_sandbox_rejects_zero_deadline) {
  static const char* const argv[] = {"sandbox-test", NULL};
  struct uav_agent_exec_params params = {
      .flags = 0,
      .argc = 1,
      .argv = argv,
      .envc = 0,
      .envp = NULL,
  };
  struct uav_sandbox sandbox = {
      .backend = UAV_SANDBOX_BACKEND_CONTAINER,
  };

  TEST_ASSERT_EQ(-1, uav_sandbox_run_program_with_deadline(&sandbox, "sample",
                                                           &params, 0));
  TEST_ASSERT_EQ(EINVAL, errno);
  return 0;
}

int main(void) {
  TEST_SUITE("Sandbox");

  RUN_TEST(test_run_sandbox_ns);
  RUN_TEST(test_run_sandbox_rejects_zero_deadline);

  return uav_test_report();
}
