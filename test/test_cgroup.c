#include "test.h"
#include "cgroup.h"
#include <sys/stat.h>
#include <unistd.h>

// Helper to check if running as root
static int is_root(void) {
  return geteuid() == 0;
}

int test_cgroup_create(void) {
  TEST_CASE("cgroup_create");

  if (!is_root()) {
    printf("SKIP (needs root)\n");
    stats.passed_tests++;
    return 0;
  }

  const char *name = "uav_test_cgroup";

  int ret = cgroup_create(name);
  TEST_ASSERT_EQ(0, ret, "Should create cgroup");

  // Verify it exists
  char path[256];
  snprintf(path, sizeof(path), "/sys/fs/cgroup/%s", name);

  struct stat st;
  TEST_ASSERT_EQ(0, stat(path, &st), "Cgroup directory should exist");
  TEST_ASSERT(S_ISDIR(st.st_mode), "Should be a directory");

  // Cleanup
  // cgroup_destroy(name);

  TEST_SUCCESS();
}

int test_cgroup_create_duplicate(void) {
  TEST_CASE("cgroup_create - duplicate");

  if (!is_root()) {
    printf("SKIP (needs root)\n");
    stats.passed_tests++;
    return 0;
  }

  const char *name = "uav_test_cgroup_dup";

  TEST_ASSERT_EQ(0, cgroup_create(name), "First create should succeed");
  TEST_ASSERT_EQ(0, cgroup_create(name), "Duplicate create should be idempotent");

  // cgroup_destroy(name);

  TEST_SUCCESS();
}

int test_cgroup_add_pid(void) {
  TEST_CASE("cgroup_add_pid");

  if (!is_root()) {
    printf("SKIP (needs root)\n");
    stats.passed_tests++;
    return 0;
  }

  const char *name = "uav_test_cgroup_pid";

  cgroup_create(name);

  pid_t pid = getpid();
  TEST_ASSERT_EQ(0, cgroup_add_pid(name, pid), "Should add pid");

  // Verify by reading cgroup.procs
  char path[256], buf[32];
  snprintf(path, sizeof(path), "/sys/fs/cgroup/%s/cgroup.procs", name);

  FILE *f = fopen(path, "r");
  TEST_ASSERT_NOT_NULL(f, "Should open cgroup.procs");

  int found = 0;
  while (fgets(buf, sizeof(buf), f)) {
    if (atoi(buf) == pid) {
      found = 1;
      break;
    }
  }
  fclose(f);

  TEST_ASSERT(found, "PID should be in cgroup");

  // Move back to root cgroup
  cgroup_add_pid("", pid);
  // cgroup_destroy(name);

  TEST_SUCCESS();
}

int main(void) {
  TEST_SUITE("Cgroup Module");

  if (!is_root()) {
    printf(COLOR_YELLOW "Warning: Running as non-root, some tests will be skipped\n" COLOR_RESET);
  }

  TEST_RUN(test_cgroup_create);
  TEST_RUN(test_cgroup_create_duplicate);
  TEST_RUN(test_cgroup_add_pid);

  TEST_REPORT();
}
