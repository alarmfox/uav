#include "uav_test.h"

TEST(test_run_sandbox_ns) {

  return 0;
}

int main (void) {

  TEST_SUITE("Sandbox");

  RUN_TEST(test_run_sandbox_ns);

  return uav_test_report();
}
