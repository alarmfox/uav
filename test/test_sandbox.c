#include "test.h"

#include <sys/stat.h>
#include <unistd.h>

#include "sandbox.h"
#include "utils.h"

static const char program[] = "#!/bin/sh\nexit 0";

// Helper to check if running as root
static int is_root(void) {
  return geteuid() == 0;
}

static int test_sandbox_run_simple_program(void) {
  TEST_CASE("sandbox - run simple program ");

  if (!is_root()) TEST_SKIP("SKIP (needs root)");

  struct uav_sandbox s = {0};
  int ret;
  char template[] = "uav_test_program_XXXXXX";

  /* Create tempfile for test program */
  TEST_ASSERT_NOT_NULL(mktemp(template), "Should create temporary name");

  /* Skip extraction for testing purposes */
  s.initialized = 1;

  /* Assume that there is a busybox fs in sandbox/ */
  ret = uav_sandbox_base_bootstrap(&s, "sandbox");
  TEST_ASSERT_EQ(0, ret, "Should bootstrap sandbox");

  /* Configure sandbox */
  const struct uav_sandbox_config config = {
    .hostip = "10.10.10.1",
    .sandboxip = "10.10.10.2",
    .hostifname = "veth1",
    .sandboxifname = "veth2",
    .prefix = 30,
  };

  ret = uav_sandbox_configure(&s, NULL, &config);
  TEST_ASSERT_EQ(0, ret, "Should configure sandbox");

  /* Write test script somewhere */
  ret = write_file_str(template, program);
  TEST_ASSERT_EQ(0, ret, "Should write simple program");

  /* Give permissions to execute */
  ret = chmod(template, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH | S_IXOTH);
  TEST_ASSERT_EQ(0, ret, "Chmod should succed");

  /* Execute in sandbox */
  ret = uav_sandbox_run_program(&s, template);
  TEST_ASSERT_EQ(0, ret, "Should execute a simple program");

  uav_sandbox_destroy(&s);

  ret = unlink(template);
  TEST_ASSERT_EQ(0, ret, "Should remove file");

  TEST_SUCCESS();
}

int main(void) {

  TEST_SUITE("Sandbox Module");

  if (!is_root()) {
    printf(COLOR_YELLOW "Warning: Running as non-root, some tests will be skipped\n" COLOR_RESET);
  }

  TEST_RUN(test_sandbox_run_simple_program);

  TEST_REPORT();
}
