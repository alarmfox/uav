#include <errno.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "sandbox.h"

/* ========================= Sandbox =========================*/

static void print_sandbox_run_help(void) {
  printf("Usage: uav sandbox run <program> \n\n");
  printf("Run a program in an isolated environment.\n\n");
  printf("Options:\n");
  printf(
      "  -b, --backend <backend> Isolation technology. 'container' or 'kvm' "
      "allowed\n");
  printf("  -h, --help              Show this help message\n\n");
  printf("Arguments:\n");
  printf("  program                 Program to execute in sandbox\n");
  printf(
      "                          If omitted, drops into interactive shell\n\n");
  printf("Examples:\n");
  printf("  uav sandbox run suspicious.sh\n");
}

static int cmd_sandbox_run(int argc, const char* argv[]) {
  int ret = EXIT_FAILURE;
  int opt;
  struct uav_sandbox s;
  enum uav_sandbox_backend backend = UAV_SANDBOX_BACKEND_CONTAINER;
  const char* program = NULL;

  static const struct option long_options[] = {
      {"backend", required_argument, NULL, 'b'},
      {"help", no_argument, NULL, 'h'},
      {NULL, 0, NULL, 0}};

  while ((opt = getopt_long(argc, (char* const*)argv, "b:h", long_options,
                            NULL)) != -1) {
    switch (opt) {
      case 'b':
        if (!strcmp(optarg, "kvm"))
          backend = UAV_SANDBOX_BACKEND_KVM;
        else if (!strcmp(optarg, "container"))
          backend = UAV_SANDBOX_BACKEND_CONTAINER;
        else {
          fprintf(stderr,
                  "[UAV] invalid sandbox backend %s. Allowed 'kvm' or "
                  "'container'.\n",
                  optarg);
          print_sandbox_run_help();
          return EXIT_FAILURE;
        }
        break;
      case 'h':
        print_sandbox_run_help();
        return EXIT_SUCCESS;
      default:
        print_sandbox_run_help();
        return EXIT_FAILURE;
    }
  }

  if (optind >= argc) {
    fprintf(stderr, "[UAV] missing program\n");
    print_sandbox_run_help();
    return EXIT_FAILURE;
  }

  if (optind + 1 != argc) {
    fprintf(stderr, "[UAV] unexpected argument: %s\n", argv[optind + 1]);
    print_sandbox_run_help();
    return EXIT_FAILURE;
  }

  program = argv[optind];

  ret = uav_sandbox_create(&s, backend);

  if (ret != 0) {
    fprintf(stderr, "[UAV] cannot create sandbox: %s\n", strerror(errno));
    ret = EXIT_FAILURE;
    goto cleanup;
  }

  ret = uav_sandbox_run_program(&s, program);
  if (ret != 0) {
    fprintf(stderr, "[UAV] cannot run sandbox: %s\n", strerror(errno));
    ret = EXIT_FAILURE;
    goto cleanup;
  }

  ret = EXIT_SUCCESS;
cleanup:
  ret = uav_sandbox_destroy(&s);
  if (ret < 0) {
    fprintf(stderr, "[UAV] cannot destroy sandbox: %s\n", strerror(errno));
    ret = EXIT_FAILURE;
  }
  return ret;
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

static int cmd_sandbox(int argc, const char* argv[]) {
  if (argc < 2) {
    print_sandbox_help();
    return EXIT_SUCCESS;
  }

  if (strcmp("run", argv[1]) == 0) return cmd_sandbox_run(argc - 1, argv + 1);
  print_sandbox_help();

  return EXIT_FAILURE;
}

/* ========================= Sandbox =========================*/

/* Command dispatch table */
struct command {
  const char* name;
  int (*func)(int argc, const char* argv[]);
  void (*help)(void);
  const char* brief;
};

static const struct command commands[] = {
    {"sandbox", cmd_sandbox, print_sandbox_help,
     "Execute and controls sandbox"},
    {NULL, NULL, NULL, NULL}};

static void print_usage(const char* progname) {
  printf("Usage: %s <command> [options]\n\n", progname);
  printf("Commands:\n");

  for (const struct command* cmd = commands; cmd->name != NULL; cmd++) {
    printf("  %-12s %s\n", cmd->name, cmd->brief);
  }

  printf("\nUse '%s <command> --help' for command-specific options\n",
         progname);
}

int main(int argc, const char* argv[]) {
  if (argc < 2) {
    print_usage(argv[0]);
    return EXIT_FAILURE;
  }

  /* Handle global flags */
  if (strcmp(argv[1], "--help") == 0 || strcmp(argv[1], "-h") == 0) {
    print_usage(argv[0]);
    return EXIT_SUCCESS;
  }

  /* Dispatch to subcommand */
  for (const struct command* cmd = commands; cmd->name != NULL; cmd++) {
    if (strcmp(argv[1], cmd->name) == 0) {
      return cmd->func(argc - 1, argv + 1);
    }
  }

  fprintf(stderr, "Unknown command: %s\n", argv[1]);
  print_usage(argv[0]);
  return EXIT_FAILURE;
}
