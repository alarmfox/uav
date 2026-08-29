#include <getopt.h>
#include <stdio.h>
#include <string.h>

#include "sandbox.h"

/* ========================= Sandbox =========================*/

static void print_sandbox_run_help(void) {
  printf("Usage: uav sandbox run <program> \n\n");
  printf("Run a program in an isolated environment.\n\n");
  printf("Arguments:\n");
  printf("  program             Program to execute in sandbox\n");
  printf("                      If omitted, drops into interactive shell\n\n");
  printf("Examples:\n");
  printf("  uav sandbox suspicious.sh\n");
  printf("  uav sandbox --rootfs custom.zip malware.elf\n");
  printf("  uav sandbox --rootfs /custom/rootfs\n");
}

static int cmd_sandbox_run(int argc, const char *argv[]) {

  int ret = -1;

  if(argc < 2) {
    print_sandbox_run_help();
    return 0;
  }

  struct uav_sandbox s;
  ret = uav_sandbox_create(&s);

  if (ret != 0) {
    fprintf(stderr, "[UAV] cannot created sandbox\n");
    return ret;
  }

  printf("[UAV] created sandbox in %s\n", s.path);

  ret = uav_sandbox_run_program(&s, argv[1]);
  if (ret != 0) {
    fprintf(stderr, "[UAV] cannot run sandbox\n");
    goto cleanup;
  }

cleanup:
  uav_sandbox_destroy(&s);
  printf("[UAV] destroyed sandbox in %s\n", s.path);
  return 0;
}

static void print_sandbox_help(void) {
  printf("Usage: uav sandbox [command]\n\n");
  printf("Run sandbox\n\n");
  printf("Available commands:\n");
  printf("  run,                Run a program in a sandbox\n");
  printf("  -h, --help          Show this help message\n\n");
  printf("Examples:\n");
  printf("  uav sandbox run suspicious.sh\n");
}

static int cmd_sandbox(int argc, const char *argv[]) {

  if(argc < 2) {
    print_sandbox_help();
    return 0;
  }

  if(strcmp("run", argv[1]) == 0)
    return cmd_sandbox_run(argc - 1, argv + 1);
  print_sandbox_help();

  return 1;
}

/* ========================= Sandbox =========================*/

/* Command dispatch table */
struct command {
  const char *name;
  int (*func)(int argc, const char *argv[]);
  void (*help)(void);
  const char *brief;
};

static const struct command commands[] = {
  {"sandbox", cmd_sandbox, print_sandbox_help, "Execute and controls sandbox"},
  { NULL, NULL, NULL, NULL }
};

static void print_usage(const char *progname) {
  printf("Usage: %s <command> [options]\n\n", progname);
  printf("Commands:\n");

  for (const struct command *cmd = commands; cmd->name != NULL; cmd++) {
    printf("  %-12s %s\n", cmd->name, cmd->brief);
  }

  printf("\nUse '%s <command> --help' for command-specific options\n", progname);
}

int main(int argc, const char *argv[]) {
  if (argc < 2) {
    print_usage(argv[0]);
    return 1;
  }

  /* Handle global flags */
  if (strcmp(argv[1], "--help") == 0 || strcmp(argv[1], "-h") == 0) {
    print_usage(argv[0]);
    return 0;
  }

  /* Dispatch to subcommand */
  for (const struct command *cmd = commands; cmd->name != NULL; cmd++) {
    if (strcmp(argv[1], cmd->name) == 0) {
      return cmd->func(argc - 1, argv + 1);
    }
  }

  fprintf(stderr, "Unknown command: %s\n", argv[1]);
  print_usage(argv[0]);
  return 1;
}
