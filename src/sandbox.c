#include <errno.h>
#include <grp.h>
#include <linux/netlink.h>
#include <net/if.h>
#include <sched.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#include "netlink.h"
#include "sandbox.h"
#include "utils.h"

/* eBPF program */
#include "sandbox.skel.h"

struct uav_sandbox_entrypoint_args {
  /* Pointer to configured uav_sandbox */
  struct uav_sandbox *s;
  /* Path of the program to execute host-side */
  char hostprogram[PATH_MAX];
  /* Communication pipes */
  int pipe_ready[2];
  int pipe_go[2];
};

static volatile sig_atomic_t stop_requested = 0;

static void sigint_handler(int sig) {
  printf("[SANDBOX] Received signal %d\n", sig);
  __atomic_store_n(&stop_requested, 1, __ATOMIC_RELAXED);
}

/* Internal prototypes */
static int sandbox_entrypoint(void *args_);
static int create_overlayfs(const char *base, const char *overlay_path);
static int setup_userns_mappings(pid_t pid, uid_t uid, gid_t gid);
static int setup_network(struct uav_sandbox *s, pid_t child);
static int setup_filesystem(const struct uav_sandbox *s);
static int sandbox_copyfile(const struct uav_sandbox *si, const char *src_path, const char *dst_name);
static int setup_userns_mappings(pid_t pid, uid_t uid, gid_t gid);
static int get_realuid(uid_t *uid, gid_t *gid);
static int create_overlayfs(const char *base, const char *overlay_path);

/* Create sandbox: extract zip directory in base root and copy entrypoint script. */
int uav_sandbox_base_bootstrap(struct uav_sandbox *si, const char *sandbox_dir) {
  int ret;

  /* Save base directory */
  strncpy(si->root, sandbox_dir, sizeof(si->root) - 1);
  si->root[sizeof(si->root) - 1] = '\0';

  /* Skip if already initialized */
  if (si->initialized) return 0;

  // Create sandbox root directory
  ret = mkdir(sandbox_dir, 0755);
  if (ret != 0 && errno != EEXIST) {
    fprintf(stderr, "[SANDBOX] cannot create directory %s: %s\n", sandbox_dir, strerror(errno));
    return -1;
  }

  /* Extract busybox zip into sandbox root */
  ret = extract_directory(BUSYBOX_ZIP, si->root);
  if (ret != 0) {
    fprintf(stderr, "[SANDBOX] cannot extract base sandbox filesystem: %s\n", strerror(errno));
    rmtree(si->root);
    return -1;
  }

  si->initialized = 1;

  return 0;
}

/* Configure sandbox with runtime data. This includes overlayfs path, IPv4 addresses. This function
 * does not perform any action apart creating the overlayfs directory, but populates structure for
 * later use */
int uav_sandbox_configure(struct uav_sandbox *s, const struct uav_cgroup_limits *limits, const struct uav_sandbox_config *config) {
  /* Create the ovelayfs. This creates a unique temporary directory */
  char template[] = "uav_sandbox_XXXXXX";
  char *p = NULL;
  size_t len = 0;

  if(mkdtemp(template) == NULL) return 1;
  if(realpath(template, s->overlay_path) == NULL) return 1;

  /* Retrieve identifier from the string provided by mkdtemp */
  /* Start from end and go backwards till '_' */
  p = s->overlay_path + strlen(s->overlay_path);
  while(*(--p) != '_') len += 1;
  strncpy(s->id, p + 1, len);
  s->id[len] = 0;

  /* Setup limits fallback to default if NULL is passed */
  const struct uav_cgroup_limits *toapply = &DEFAULT_LIMITS;
  if(limits) toapply = limits;
  memcpy(&s->limits, toapply, sizeof(struct uav_cgroup_limits));

  /* Parse IP */
  if (inet_pton(AF_INET, config->hostip, &s->hostip) != 1) {
    fprintf(stderr, "[NETLINK] invalid IP: %s\n", config->hostip);
    return 1;
  }

  if (inet_pton(AF_INET, config->sandboxip, &s->sandboxip) != 1) {
    fprintf(stderr, "[NETLINK] invalid IP: %s\n", config->sandboxip);
    return 1;
  }

  /* Allocate stack for the sandbox */
  s->stack = malloc(s->limits.stack_size);
  if(!s->stack) {
    fprintf(stderr, "[SANDBOX] cannot allocate sandbox stack (size=%zu)", s->limits.stack_size);
    return 1;
  }

  /* Copy ifnames */
  safe_strcpy(s->hostifname, config->hostifname, IFNAMSIZ);
  safe_strcpy(s->sandboxifname, config->sandboxifname, IFNAMSIZ);

  /* Save prefix */
  s->prefix = config->prefix;

  return 0;
}

/* Execute a program in the sandbox. This includes spawning a new process and attaching the ebpf program */
int uav_sandbox_run_program(struct uav_sandbox *s, const char *program) {
  /* Sanity check */
  if (!s) return 1;

  int pipe_ready[2] = { -1, -1 };
  int pipe_go[2]    = { -1, -1 };
  int wstatus, ret = 1;
  pid_t child = -1;
  uid_t uid;
  gid_t gid;
  ssize_t nbytes;
  char c = 'E';
  unsigned int cgid;
  unsigned char *stack_top = s->stack + s->limits.stack_size;
  char *path = NULL;
  size_t len;
  struct uav_sandbox_entrypoint_args *args = NULL;

  /* Pipes */
  ret = pipe(pipe_ready);
  if (ret < 0) goto cleanup;

  ret = pipe(pipe_go);
  if (ret < 0) goto cleanup;

  /* Args */
  args = malloc(sizeof(struct uav_sandbox_entrypoint_args));
  if (!args) goto cleanup;

  args->s = malloc(sizeof(struct uav_sandbox));
  if (!args->s) goto cleanup;

  memcpy(args->s, s, sizeof(struct uav_sandbox));
  memcpy(args->pipe_ready, pipe_ready, sizeof(pipe_ready));
  memcpy(args->pipe_go, pipe_go, sizeof(pipe_go));
  safe_strcpy(args->hostprogram, program, PATH_MAX);

  /* Create the overlayfs for this instance. */
  ret = setup_filesystem(s);
  if(ret) goto cleanup;

  /* Give permission to sandbox folders */
  ret = get_realuid(&uid, &gid);
  if(ret) goto cleanup;

  const char *dirs[] = {
    "/merged",
    "/upper",
    "/work",
    "/",
    NULL
  };

  len = strlen(s->overlay_path) + strlen("/merged/entrypoint.sh") + 1;
  path = malloc(len);
  if(!path) return 1;

  for(const char **p = dirs; *p != NULL; p++) {
    snprintf(path, len, "%s%s", s->overlay_path, *p);
    ret = chown(path, uid, gid);
    if(ret) break;
  }

  if(ret) goto cleanup;

  /* Write entrypoint */
  snprintf(path, len, "%s/merged/entrypoint.sh", s->overlay_path);
  ret = write_file_str(path, entrypoint);

  if(ret) goto cleanup;

  /* Give real user exec permissions on the entrypoint */
  ret = chown(path, uid, gid);
  if(ret) goto cleanup;

  ret = chmod(path, S_IRUSR | S_IXUSR);
  if(ret) goto cleanup;

  /* Configure signals before cloning */
  struct sigaction sa = {
    .sa_handler = sigint_handler,
    .sa_flags = 0,
  };
  sigemptyset(&sa.sa_mask);
  sigaction(SIGINT, &sa, NULL);

  /* Clone */
  child = clone(sandbox_entrypoint, stack_top,
      CLONE_NEWNS |
      CLONE_NEWUTS |
      CLONE_NEWPID |
      CLONE_NEWNET |
      CLONE_NEWCGROUP |
      CLONE_NEWUSER |
      SIGCHLD,
      args);

  if (child < 0) goto cleanup;

  /* Parent-only pipe usage */
  close(pipe_ready[1]); pipe_ready[1] = -1;
  close(pipe_go[0]);    pipe_go[0]    = -1;

  /* Wait for child readiness */
  nbytes = read(pipe_ready[0], &c, 1);
  if (nbytes != 1 || c != 'R') goto cleanup;

  close(pipe_ready[0]); pipe_ready[0] = -1;

  /* Setup network */
  ret = setup_network(s, child);
  if (ret) goto cleanup;

  /* Cgroup */
  ret = cgroup_create("uav-cgroup");
  if (ret) goto cleanup;

  ret = cgroup_add_pid("uav-cgroup", child);
  if (ret) goto cleanup;

  ret = cgroup_set_limits("uav-cgroup", &s->limits);
  if (ret) goto cleanup;

  /* eBPF */
  s->skel = sandbox_bpf__open();
  if (!s->skel) goto cleanup;

  cgid = cgroup_getid("uav-cgroup");
  if (!cgid) goto cleanup;

  s->skel->rodata->target_cgroup_id = cgid;

  ret = sandbox_bpf__load(s->skel);
  if (ret) goto cleanup;

  ret = sandbox_bpf__attach(s->skel);
  if (ret) goto cleanup;

  ret = setup_userns_mappings(child, uid, gid);
  if (ret) goto cleanup;

  /* Start capture thread for veth */

  /* Allow child to run */
  c = 'X';
  ret = 0;

  printf("[SANDBOX] running process %d\n", child);

cleanup:
  if(path) {
    free(path);
    path = NULL;
  }
  /* Notify child */
  if (pipe_go[1] != -1) {
    write(pipe_go[1], &c, 1);
    close(pipe_go[1]);
  }

  /* Wait for child to exit */
  if (child > 0) {
    pid_t r;
    while(1) {
      r = waitpid(child, &wstatus, 0);
      if (r == -1) {
        if (errno == EINTR) {
          /* If stop is requested just kill the process and wait */
          if(__atomic_load_n(&stop_requested, __ATOMIC_RELAXED) == 1) {
            kill(child, SIGKILL);
            continue;
          }
          continue;
        }
      }
      break;
    }

    if (WIFEXITED(wstatus)) {
      const int es = WEXITSTATUS(wstatus);
      fprintf(stderr, "[SANDBOX] process exited status=%d\n", es);
      if(es != 0) ret = 1;
    } else if (WIFSIGNALED(wstatus)) {
      fprintf(stderr, "[SANDBOX] process killed by signal %d\n", WTERMSIG(wstatus));
    } else if (WIFSTOPPED(wstatus)) {
      fprintf(stderr, "[SANDBOX] process stopped by signal %d\n", WSTOPSIG(wstatus));
    } else if (WIFCONTINUED(wstatus)) {
      fprintf(stderr,"[SANDBOX] process continued\n");
    }

  }

  if (s->skel) {
    sandbox_bpf__destroy(s->skel);
    s->skel = NULL;
  }

  if (args) {
    if (args->s) free(args->s);
    free(args);
  }

  if (pipe_ready[0] != -1) close(pipe_ready[0]);
  if (pipe_ready[1] != -1) close(pipe_ready[1]);
  if (pipe_go[0]    != -1) close(pipe_go[0]);
  if (pipe_go[1]    != -1) close(pipe_go[1]);

  if (ret && child > 0)
    kill(child, SIGKILL);

  if(ret)
    fprintf(stderr, "[SANDBOX] error during sandboxed execution: %s\n", strerror(errno));

  return ret;
}

/* Destroy a sandbox by removing its filesystem tree */
void uav_sandbox_destroy(struct uav_sandbox *s) {
  int ret;
  size_t len;
  char *path = NULL;

  const char *dirs[] = {
    "/merged/dev/pts",
    "/merged/tmp",
    "/merged/proc",
    "/merged/dev",
    "/merged",
    NULL
  };

  len = strlen(s->overlay_path) + strlen("/merged/dev/pts") + 1;
  path = malloc(len);
  if(!path) return;

  for(const char **p = dirs; *p != NULL; p++) {
    snprintf(path, len, "%s%s", s->overlay_path, *p);
    ret = umount2(path, MNT_FORCE);
    if(ret) fprintf(stderr, "[SANDBOX] cannot unmount %s: %s\n", path, strerror(errno)); 
  }

  free(path);
  path = NULL;

  /* Remove tree */
  ret = rmtree(s->overlay_path);
  if(ret) fprintf(stderr, "[SANDBOX] cannot remove tree at %s: %s\n", s->overlay_path, strerror(errno));

  /* Remove the stack */
  if(s->stack) free(s->stack);
  s->stack = NULL;
}

/* Entrypoint process for sandbox. This should PID 1 for this namespace. The entrypoint coordinates
 * with parent for networking and some configuration (ie. attach the eBPF to the specific process).
 * The function uses private mount /, pivot_root to create a fully isolated process.
 * */
static int sandbox_entrypoint(void *args_) {
  int ret;
  char c;
  char *newroot, *oldroot;
  struct uav_sandbox_entrypoint_args *args = args_;
  const struct uav_sandbox *s = args->s;
  int *pipe_ready = args->pipe_ready;
  int *pipe_go = args->pipe_go;
  const char *err_msg = NULL;
  size_t newroot_len = strlen(s->overlay_path) + strlen("/merged") + 1;
  size_t oldroot_len = strlen(s->overlay_path) + strlen("/merged") + strlen("/oldroot") + 1;

  newroot = malloc(newroot_len);
  oldroot = malloc(oldroot_len);

  if(!newroot || !oldroot) goto fail;

  /* 1. Sync with Parent */
  close(pipe_go[1]);
  close(pipe_ready[0]);

  ret = write(pipe_ready[1], "R", 1);
  if (ret != 1) {
    err_msg = "write(ready)";
    goto fail;
  }

  ret = read(pipe_go[0], &c, 1);
  if (ret != 1) {
    err_msg = "read(go)";
    goto fail;
  }

  if (c == 'E') _exit(1);

  close(pipe_ready[1]);
  close(pipe_go[0]);

  /* 2. Prepare paths */
  snprintf(newroot, newroot_len, "%s/merged", s->overlay_path);
  snprintf(oldroot, oldroot_len, "%s/merged/oldroot", s->overlay_path);

  /* 3. Setup Mount Namespace Requirements */
  // Change propagation to private to satisfy pivot_root requirements
  ret = mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL);
  if (ret < 0) {
    err_msg = "mount(/, MS_PRIVATE)";
    goto fail;
  }

  /* CRITICAL: pivot_root requires new_root to be a mount point. 
   * We bind-mount the directory to itself to ensure this. */
  ret = mount(newroot, newroot, NULL, MS_BIND | MS_REC, NULL);
  if (ret < 0) {
    err_msg = "bind mount newroot";
    goto fail;
  }

  /* 4. File operations before pivot */
  ret = sandbox_copyfile(s, args->hostprogram, "/malware.sh");
  if (ret != 0) {
    err_msg = "copy malware.sh";
    goto fail;
  }

  ret = mkdir(oldroot, 0755);
  if (ret < 0 && errno != EEXIST) {
    err_msg = "mkdir oldroot";
    goto fail;
  }

  /* 5. The Pivot */
  ret = syscall(SYS_pivot_root, newroot, oldroot);
  if (ret < 0) {
    err_msg = "pivot_root";
    goto fail;
  }

  ret = chdir("/");
  if (ret < 0) {
    err_msg = "chdir(/)";
    goto fail;
  }

  /* 6. Cleanup Host Links */
  // MNT_DETACH allows us to unmount even if the FS is busy
  ret = umount2("/oldroot", MNT_DETACH);
  if (ret < 0) {
    err_msg = "umount2(oldroot)";
    goto fail;
  }

  ret = rmdir("/oldroot");

  if (ret < 0) {
    err_msg = "rmdir(oldroot)";
    goto fail;
  }

  /* Drop capabilities */

  /* 7. Drop privileges (Set UID/GID to 0 inside namespace -> maps to userid outside) */
  ret = setresgid(0, 0, 0);
  if (ret < 0) {
    err_msg = "setresgid(0, 0, 0)";
    goto fail;
  }
  ret = setresuid(0, 0, 0);
  if (ret < 0) {
    err_msg = "setresuid(0, 0, 0)";
    goto fail;
  }

  ret = setgroups(0, NULL);
  if (ret < 0) {
    err_msg = "setgroups(0, NULL)";
    goto fail;
  }

  /* Set hostname */
  ret = sethostname(s->id, strlen(s->id));
  if(ret) goto fail;

  ret = mkdir("/etc", 755);
  if(ret) goto fail;

  /* Free path */
  free(oldroot);
  free(newroot);
  oldroot = NULL;
  newroot = NULL;

  write_file_str("/etc/hostname", s->id);

  /* 8. Execute */
  char *const argv[] = { "/bin/sh", "/entrypoint.sh", "/malware.sh", NULL };
  execv("/bin/sh", argv);

  /* Execv only returns on error */
  err_msg = "execv";

fail:
  if (err_msg) {
    fprintf(stderr, "[SANDBOX] cannot start process %s: %s\n", err_msg, strerror(errno));
  }
  if(oldroot) free(oldroot);
  if(newroot) free(newroot);
  _exit(1);
}

/* Set up a virtual ethernet pair. We need to create a veth pair to inspect all networking traffic
 * coming from the sandbox. This happens through netlink messages. The host-side can be configured
 * immediately, but sandbox-side we need to move this process in the sandbox netns and configure the
 * pair from there. This implies closing the current netlink socket (as it will be different under the
 * other netns) and reopening to finish the configuration. The sandbox netns will have a peer veth
 * with just a routing rule to send everything to the host side. */
static int setup_network(struct uav_sandbox *s, pid_t child) {

  int ret = -1, nlsockfd = -1, original_netnsfd = -1, child_netnsfd = -1;
  struct sockaddr_nl sa = {0};
  char child_netns_path[PATH_MAX];

  /* Get child's network namespace fd */
  snprintf(child_netns_path, sizeof(child_netns_path), "/proc/%d/ns/net", child);
  child_netnsfd = open(child_netns_path, O_RDONLY);
  if (child_netnsfd < 0) {
    fprintf(stderr, "[SANDBOX] cannot open child netns: %s\n", strerror(errno));
    goto exit;
  }

  /* Save our original netns */
  original_netnsfd = open("/proc/self/ns/net", O_RDONLY);
  if (original_netnsfd < 0) {
    fprintf(stderr, "[SANDBOX] cannot open original netns: %s\n", strerror(errno));
    goto exit;
  }

  /* Open netlink socket */
  nlsockfd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);

  if (nlsockfd < 0) goto exit;

  sa.nl_family = AF_NETLINK;
  sa.nl_pid = 0;

  ret = bind(nlsockfd, (struct sockaddr *)&sa, sizeof(sa));
  if (ret < 0) goto exit;

  /* Create veth pair */
  ret = create_veth_pair(nlsockfd, s->hostifname, s->sandboxifname);
  if(ret) goto exit;

  /* Set host-side up */
  ret = set_link_up(nlsockfd, s->hostifname);
  if(ret) goto exit;

  /* Add an IP address to the host-side. Use just IPv4 for now */
  ret = add_ip_addr(nlsockfd, s->hostifname, &s->hostip, s->prefix);
  if(ret) goto exit;

  ret = move_if_to_netns(nlsockfd, s->sandboxifname, child_netnsfd);
  if(ret) goto exit;

  /* Close netlink socket to reopen it in the new netns */
  close(nlsockfd);

  ret = setns(child_netnsfd, CLONE_NEWNET);;
  if(ret < 0) goto exit;

  /* Reopen the socket */
  nlsockfd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);

  if (nlsockfd < 0) goto exit;

  sa.nl_family = AF_NETLINK;
  sa.nl_pid = 0;

  ret = bind(nlsockfd, (struct sockaddr *)&sa, sizeof(sa));
  if (ret < 0) goto exit;

  /* Set sandbox-side up */
  ret = set_link_up(nlsockfd, s->sandboxifname);
  if(ret) goto exit;

  ret = set_link_up(nlsockfd, "lo");
  if(ret) goto exit;

  /* Add an IP address to the sandbox-side. Use just IPv4 for now */
  ret = add_ip_addr(nlsockfd, s->sandboxifname, &s->sandboxip, s->prefix);
  if(ret) goto exit;

  /* Add default route towards host-side. */
  ret = add_default_route(nlsockfd, &s->hostip, s->sandboxifname);
  if(ret) goto exit;

  /* Go back to original netns */
  ret = setns(original_netnsfd, CLONE_NEWNET);;
  if(ret < 0) goto exit;

  ret = 0;

exit:
  if (nlsockfd > 0) close(nlsockfd);
  if(child_netnsfd > 0 ) close(child_netnsfd);
  if(original_netnsfd > 0 ) close(original_netnsfd);
  if (ret) fprintf(stderr, "[SANDBOX] cannot configure network: %s\n", strerror(errno));
  return ret;
}

/* Setup filesystem: create the overlayfs (the base directory of the running instance) and mount /proc and /tmp */
static int setup_filesystem(const struct uav_sandbox *s) {
  int ret;
  char *path = NULL, options[256];
  size_t len;

  /* Mount overlayfs from sandbox base */
  ret = create_overlayfs(s->root, s->overlay_path);
  if(ret) {
    fprintf(stderr, "[SANDBOX] cannot create overlayfs: %s\n", strerror(errno));
    return 1;
  }

  /* Create /tmp and mount tmpfs */
  len = strlen(s->overlay_path) + strlen("/merged/tmp") + 1;
  path = malloc(len);
  if(!path) return 1;
  
  snprintf(path, len, "%s/merged/tmp", s->overlay_path);
  mkdir(path, 0755);

  snprintf(options, sizeof(options), "size=%zu", s->limits.tmpfs_size);
  ret = mount("tmpfs", path, "tmpfs", 0, options);
  if(ret) {
    free(path);
    return 1;
  }
  free(path);

  /* Create /proc and mount procfs */
  len = strlen(s->overlay_path) + strlen("/merged/proc") + 1;
  path = malloc(len);
  if(!path) return 1;

  snprintf(path, len,"%s/merged/proc", s->overlay_path);
  mkdir(path, 0755);

  ret = mount("proc", path, "proc", MS_NOSUID | MS_NOEXEC | MS_NODEV, NULL);
  if(ret) {
    free(path);
    return 1;
  }
  free(path);

  /* Create /dev and mount it as a tmpfs*/
  len = strlen(s->overlay_path) + strlen("/merged/dev") + 1;
  path = malloc(len);
  if(!path) return 1;

  snprintf(path, len, "%s/merged/dev", s->overlay_path);
  mkdir(path, 0755);

  ret = mount("tmpfs", path, "tmpfs", MS_NOSUID | MS_NOEXEC, "mode=755");
  if(ret) {
    free(path);
    return 1;
  }
  free(path);

  /* Required device nodes */
  /* Allocate once since this the bigger size, reuse path for allocations */
  len = strlen(s->overlay_path) + strlen("/merged/dev/null") + 1;
  path = malloc(len);
  if(!path) return 1;

  snprintf(path, len, "%s/merged/dev/null", s->overlay_path);
  mknod(path, S_IFCHR | 0666, makedev(1, 3));

  snprintf(path, len, "%s/merged/dev/zero", s->overlay_path);
  mknod(path, S_IFCHR | 0666, makedev(1, 5));

  snprintf(path, len, "%s/merged/dev/tty", s->overlay_path);
  mknod(path, S_IFCHR | 0666, makedev(5, 0));

  /* /dev/pts */
  snprintf(path, len, "%s/merged/dev/pts", s->overlay_path);
  mkdir(path, 0755);

  ret = mount("devpts", path, "devpts", 0,
      "newinstance,ptmxmode=0666,mode=620");
  if (ret) return 1;

  /* /dev/ptmx */
  snprintf(path, len, "%s/merged/dev/ptmx", s->overlay_path);
  ret = symlink("/dev/pts/ptmx", path);
  if (ret) return 1;

  free(path);

  return 0;
}

/* Copy a file from `src_path` in `dst_name` (preserving permissions) relative to sandbox */
static int sandbox_copyfile(const struct uav_sandbox *s, const char *src, const char *dst) {
  size_t dstlen = strlen(s->overlay_path) + strlen("/merged/") + strlen(dst) + 1;
  char *dstpath = malloc(dstlen);
  struct stat statbuf;
  int ret;

  if(!dstpath) return 1;

  /* Skip '/' if specified  */
  if(dst[0] == '/') dst++;

  snprintf(dstpath, dstlen, "%s/merged/%s", s->overlay_path, dst);

  /* Copy file into sandbox */
  ret = copyfile(src, dstpath);
  if (ret != 0) {
    fprintf(stderr, "[SANDBOX] cannot copy file to sandbox: %s\n", strerror(errno));
    free(dstpath);
    dstpath = NULL;
    return 1;
  }

  /* Get permissions */
  ret = stat(src, &statbuf);
  if (ret != 0) {
    fprintf(stderr, "[SANDBOX] cannot stat file: %s\n", strerror(errno));
    free(dstpath);
    dstpath = NULL;
    return 1;
  }

  /* Apply permissions to copied file */
  ret = chmod(dstpath,  statbuf.st_mode);
  if (ret != 0) {
    fprintf(stderr, "[SANDBOX] cannot chmod file: %s\n", strerror(errno));
    free(dstpath);
    dstpath = NULL;
    return 1;
  }

  free(dstpath);
  dstpath = NULL;

  return 0;
}

/* Create runtime fs for the sandbox starting from `base`. This allows to easily spin up and destroy 
 * sandbox s. */
static int create_overlayfs(const char *base, const char *overlay_path) {
  int ret = -1;
  char upper[PATH_MAX], work[PATH_MAX], merged[PATH_MAX];
  char *opts = NULL;
  size_t opts_len;

  /* Validate inputs */
  if (!base || !overlay_path) {
    errno = EINVAL;
    return -1;
  }

  /* Build paths with overflow checking */
  if (snprintf(upper, sizeof(upper), "%s/upper", overlay_path) >= (int)sizeof(upper)) {
    fprintf(stderr, "[OVERLAYFS] upper path too long\n");
    errno = ENAMETOOLONG;
    return -1;
  }

  if (snprintf(work, sizeof(work), "%s/work", overlay_path) >= (int)sizeof(work)) {
    fprintf(stderr, "[OVERLAYFS] work path too long\n");
    errno = ENAMETOOLONG;
    return -1;
  }

  if (snprintf(merged, sizeof(merged), "%s/merged", overlay_path) >= (int)sizeof(merged)) {
    fprintf(stderr, "[OVERLAYFS] merged path too long\n");
    errno = ENAMETOOLONG;
    return -1;
  }

  /* Create directories */
  ret = mkdir(upper, 0755);
  if (ret != 0 && errno != EEXIST) {
    fprintf(stderr, "[OVERLAYFS] mkdir(%s) failed: %s\n", upper, strerror(errno));
    return -1;
  }

  ret = mkdir(work, 0755);
  if (ret != 0 && errno != EEXIST) {
    fprintf(stderr, "[OVERLAYFS] mkdir(%s) failed: %s\n", work, strerror(errno));
    goto cleanup_upper;
  }

  ret = mkdir(merged, 0755);
  if (ret != 0 && errno != EEXIST) {
    fprintf(stderr, "[OVERLAYFS] mkdir(%s) failed: %s\n", merged, strerror(errno));
    goto cleanup_work;
  }

  /* Allocate options string dynamically (safer than PATH_MAX) */
  opts_len = strlen("lowerdir=,upperdir=,workdir=") + strlen(base) + strlen(upper) + strlen(work) + 1;

  opts = malloc(opts_len);
  if (!opts) {
    fprintf(stderr, "[OVERLAYFS] out of memory\n");
    goto cleanup_merged;
  }

  snprintf(opts, opts_len, "lowerdir=%s,upperdir=%s,workdir=%s", base, upper, work);

  /* Mount overlay */
  ret = mount("overlay", merged, "overlay", 0, opts);
  if (ret != 0) {
    fprintf(stderr, "[OVERLAYFS] mount failed: %s\n", strerror(errno));
    fprintf(stderr, "[OVERLAYFS] options: %s\n", opts);
    goto cleanup_merged;
  }

  /* Success */
  free(opts);
  return 0;

cleanup_merged:
  rmdir(merged);
cleanup_work:
  rmdir(work);
cleanup_upper:
  rmdir(upper);
  free(opts);
  return -1;
}

/* Retrieve real uid and gid even if running with sudo */
static int get_realuid(uid_t *uid, gid_t *gid) {
  if (getuid() != 0) {
    *uid = getuid();
    *gid = getgid();
    return 0;
  }

  const char *sudo_uid = secure_getenv("SUDO_UID");
  if (sudo_uid == NULL) {
    printf("environment variable `SUDO_UID` not found\n");
    return -1;
  }
  errno = 0;
  *uid = (uid_t)strtoll(sudo_uid, NULL, 10);
  if (errno != 0) {
    perror("under-/over-flow in converting `SUDO_UID` to integer");
    return -1;
  }

  const char *sudo_gid = secure_getenv("SUDO_GID");
  if (sudo_gid == NULL) {
    printf("environment variable `SUDO_GID` not found\n");
    return -1;
  }
  errno = 0;
  *gid = (gid_t)strtoll(sudo_gid, NULL, 10);
  if (errno != 0) {
    perror("under-/over-flow in converting `SUDO_GID` to integer");
    return -1;
  }
  return 0;
}

/* Setup user namespace UID/GID mapping before entering sandbox */
static int setup_userns_mappings(pid_t pid, uid_t uid, gid_t gid) {
  char path[PATH_MAX];
  char mapping[256];
  int fd;

  /* Write UID mapping: <inside-uid> <outside-uid> <count> */
  snprintf(path, sizeof(path), "/proc/%d/uid_map", pid);
  fd = open(path, O_WRONLY);
  if (fd < 0) {
    perror("open uid_map");
    return -1;
  }

  /* Map UID 0 inside to our UID outside (single user mapping) */
  snprintf(mapping, sizeof(mapping), "0 %d 1", uid);
  if (write(fd, mapping, strlen(mapping)) < 0) {
    perror("write uid_map");
    close(fd);
    return -1;
  }
  close(fd);

  /* Disable setgroups (required before GID mapping) */
  snprintf(path, sizeof(path), "/proc/%d/setgroups", pid);
  fd = open(path, O_WRONLY);
  if (fd >= 0) {
    write(fd, "allow", 5);
    close(fd);
  }

  /* Write GID mapping */
  snprintf(path, sizeof(path), "/proc/%d/gid_map", pid);
  fd = open(path, O_WRONLY);
  if (fd < 0) {
    perror("open gid_map");
    return -1;
  }

  snprintf(mapping, sizeof(mapping), "0 %d 1", gid);
  if (write(fd, mapping, strlen(mapping)) < 0) {
    perror("write gid_map");
    close(fd);
    return -1;
  }
  close(fd);

  return 0;
}
