#include <getopt.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "sandbox.h"
#include "utils.h"

/* Command help */
static void print_scan_help(void) {
  printf("Usage: uav scan [options] <file>\n\n");
  printf("Scan a file for malware signatures.\n");
  printf("(Not yet implemented)\n");
}

static void print_protect_help(void) {
  printf("Usage: uav protect [options]\n\n");
  printf("Enable runtime malware protection.\n");
  printf("(Not yet implemented)\n");
}

static void print_sandbox_help(void) {
  printf("Usage: uav sandbox [options] [program]\n\n");
  printf("Run a program in an isolated sandbox environment.\n\n");
  printf("Options:\n");
  printf("  -r, --rootfs PATH   Path to rootfs directory or .zip file\n");
  printf("                      (default: sandbox/)\n");
  printf("  -h, --help          Show this help message\n\n");
  printf("Arguments:\n");
  printf("  program             Program to execute in sandbox\n");
  printf("                      If omitted, drops into interactive shell\n\n");
  printf("Examples:\n");
  printf("  uav sandbox suspicious.sh\n");
  printf("  uav sandbox --rootfs custom.zip malware.elf\n");
  printf("  uav sandbox --rootfs /custom/rootfs\n");
}

/* Command functions */
static int cmd_sandbox(int argc, char **argv) {
  int ret = 1;
  int opt;
  int extract_zip = 0;

  const char *rootfs_arg = NULL;   /* user-provided */
  char *rootfs_path = NULL;        /* owned, possibly temp */
  const char *program = NULL;

  struct uav_sandbox s = {0};

  static const struct option long_options[] = {
    { "rootfs", required_argument, NULL, 'r' },
    { "help",   no_argument,       NULL, 'h' },
    { NULL,     0,                 NULL,  0  }
  };

  while ((opt = getopt_long(argc, argv, "r:h", long_options, NULL)) != -1) {
    switch (opt) {
      case 'r':
        rootfs_arg = optarg;
        size_t len = strlen(rootfs_arg);
        extract_zip = (len > 4 && strcmp(rootfs_arg + len - 4, ".zip") == 0);
        break;
      case 'h':
        print_sandbox_help();
        return 0;
      default:
        print_sandbox_help();
        return 1;
    }
  }

  if (!rootfs_arg) {
    fprintf(stderr, "[SANDBOX] cannot start: missing rootfs\n");
    return 1;
  }

  if (optind < argc) {
    program = argv[optind];
  }

  /* Prepare rootfs */
  if (extract_zip) {
    char template[] = "/tmp/uav_rootfs_XXXXXX";

    if (!mkdtemp(template)) {
      fprintf(stderr, "mkdtemp failed: %s\n", strerror(errno));
      goto cleanup;
    }

    if (zip_extract_directory(rootfs_arg, template) != 0) {
      fprintf(stderr, "Failed to extract rootfs: %s\n", strerror(errno));
      rmtree(template);
      goto cleanup;
    }

    rootfs_path = strdup(template);
    if (!rootfs_path) {
      fprintf(stderr, "Out of memory\n");
      rmtree(template);
      goto cleanup;
    }
  } else {
    rootfs_path = strdup(rootfs_arg);
    if (!rootfs_path) {
      fprintf(stderr, "Out of memory\n");
      goto cleanup;
    }
  }

  safe_strcpy(s.root, rootfs_path, PATH_MAX);

  const struct uav_sandbox_config config = {
    .hostip         = "10.10.10.1",
    .sandboxip      = "10.10.10.2",
    .hostifname     = "veth1",
    .sandboxifname  = "veth2",
    .prefix         = 30,
  };

  if (uav_sandbox_configure(&s, NULL, &config) != 0) {
    fprintf(stderr, "Failed to configure sandbox: %s\n", strerror(errno));
    goto cleanup;
  }

  if (program) {
    ret = uav_sandbox_run_program(&s, program);
  } else {
    const char shell_script[] = "/tmp/uav_shell.sh";

    if (write_file_str(shell_script, "#!/bin/sh\nexec /bin/sh") != 0 ||
        chmod(shell_script, 0755) != 0) {
      fprintf(stderr, "Failed to create shell script: %s\n", strerror(errno));
      goto cleanup;
    }

    ret = uav_sandbox_run_program(&s, shell_script);
    unlink(shell_script);
  }

cleanup:
  uav_sandbox_destroy(&s);

  if (extract_zip && rootfs_path) {
    rmtree(rootfs_path);
  }

  free(rootfs_path);
  return ret;
}

/* Help functions */
static int cmd_scan(int argc, char **argv) {
  (void)argc;
  (void)argv;
  fprintf(stderr, "Scan mode not yet implemented\n");
  return 1;
}

static int cmd_protect(int argc, char **argv) {
  (void)argc;
  (void)argv;
  fprintf(stderr, "Protection mode not yet implemented\n");
  return 1;
}

/* Command dispatch table */
struct command {
  const char *name;
  int (*func)(int argc, char **argv);
  void (*help)(void);
  const char *brief;
};

static const struct command commands[] = {
  { "sandbox", cmd_sandbox, print_sandbox_help, "Run programs in isolated environment" },
  { "scan", cmd_scan, print_scan_help, "Scan files for malware signatures" },
  { "protect", cmd_protect, print_protect_help, "Enable runtime protection" },
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

int main(int argc, char **argv) {
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
