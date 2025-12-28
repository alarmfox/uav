#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "sandbox.h"

int main(void) {
  int ret;
  const char path[] = "sample.sh";
  struct uav_sandbox s = {0};

  /* Skip extraction for testing purposes */
  s.initialized = 1;

  /* Execute the program in a sandbox for demonstration purposes */
  ret = uav_sandbox_base_bootstrap(&s, "sandbox");
  if (ret != 0) {
    fprintf(stderr, "[SANDBOX] cannot bootstrap sandbox\n");
    exit(1);
  }

  /* Configure sandbox */
  const struct uav_sandbox_config config = {
    .hostip = "10.10.10.1",
    .sandboxip = "10.10.10.2",
    .hostifname = "veth1",
    .sandboxifname = "veth2",
    .prefix = 30,
  };

  ret = uav_sandbox_configure(&s, NULL, &config);
  if (ret != 0) {
    fprintf(stderr, "[SANDBOX] cannot configure: %s\n", strerror(errno));
    goto exit;
  }

  /* Run the file in sandbox */
  ret = uav_sandbox_run_program(&s, path);
  if (ret != 0) {
    fprintf(stderr, "[SANDBOX] cannot execute \"%s\" in sandbox: %s\n", path, strerror(errno));
    goto exit;
  }

exit:
  uav_sandbox_destroy(&s);

  return 0;
}
