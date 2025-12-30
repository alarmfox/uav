#include <grp.h>
#include <linux/netlink.h>
#include <net/if.h>
#include <poll.h>
#include <linux/prctl.h>
#include <sys/prctl.h>
#include <pthread.h>
#include <sched.h>
#include <stdlib.h>
#include <string.h>
#include <sys/capability.h>
#include <sys/eventfd.h>
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

/* Message types for parent-child communication */
enum sandbox_msg_type {
	MSG_INVALID = 0,
	MSG_CHILD_READY,          /* Child: initial setup done, ready for parent */
	MSG_PARENT_GO,            /* Parent: continue with next phase */
	MSG_CHILD_USERNS_READY,   /* Child: user namespace created */
	MSG_PARENT_MAPPINGS_DONE, /* Parent: user mappings configured */
	MSG_CHILD_ERROR,          /* Child: error occurred */
	MSG_PARENT_ERROR,         /* Parent: error occurred */
	MSG_CHILD_EXIT,           /* Child: exiting normally */
};

struct sandbox_msg {
	enum sandbox_msg_type type;
	int data;  /* Optional data (e.g., error code, fd) */
};

struct sandbox_entrypoint_args {
  /* Pointer to configured uav_sandbox */
  struct uav_sandbox *s;
  /* Path of the program to execute host-side */
  char hostprogram[PATH_MAX];
  /* Single bidirectional communication socket */
  int comm_sock;
};

/* These 2 function are implemented in src/capture.c because we cannot put together libbpf and libpcap stuff.
 * More on: https://github.com/libbpf/libbpf/issues/376 */
int pcap_start_capture(struct uav_sandbox *);
int pcap_stop_capture(struct uav_sandbox *);

/* Internal prototypes */
static int sandbox_entrypoint(void *args_);
static int create_overlayfs(const char *base, const char *overlay_path);
static int setup_network(struct uav_sandbox *s, pid_t child);
static int setup_filesystem(const struct uav_sandbox *s);
static int sandbox_copyfile(const struct uav_sandbox *si, const char *src_path, const char *dst_name);
static int setup_userns_mappings(pid_t pid, uid_t uid, gid_t gid);
static int get_realuid(uid_t *uid, gid_t *gid);
static int create_overlayfs(const char *base, const char *overlay_path);

/* Helper functions for socket communication */
static int send_msg(int sockfd, enum sandbox_msg_type type, int data);
static int recv_msg(int sockfd, struct sandbox_msg *msg);

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
  ret = zip_extract_directory(BUSYBOX_ZIP, si->root);
  if (ret != 0) {
    fprintf(stderr, "[SANDBOX] cannot extract base sandbox filesystem: %s\n", strerror(errno));
    rmtree(si->root);
    return -1;
  }

  si->initialized = 1;

  return 0;
}

/* Configure sandbox with runtime data. This includes overlayfs path, IPv4 addresses. This function
 * does not perform any action apart creating the base directory, but populates structure for
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
  if (!s || !program) return 1;

  int ret = 1, wstatus, sockfd[2];
  pid_t child = -1;
  uid_t uid;
  gid_t gid;
  unsigned int cgid;
  unsigned char *stack_top = s->stack + s->limits.stack_size;
  struct sandbox_entrypoint_args entrypoint_args = {0};
  char *path = NULL;
  struct sandbox_msg msg;
  size_t pathlen;

  /* Create a socket pair for bidirectional communication */
  if (socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, sockfd) < 0) {
    fprintf(stderr, "[SANDBOX] cannot create socket pair: %s\n", strerror(errno));
    goto cleanup;
  }

  /* Args */
  entrypoint_args.s = s;
  safe_strcpy(entrypoint_args.hostprogram, program, PATH_MAX);
  entrypoint_args.comm_sock = sockfd[1];  /* Child gets one end */

  /* Create the filesystem */
  ret = setup_filesystem(s);
  if(ret) goto cleanup;

  /* Get real uid/gid for mapping */
  ret = get_realuid(&uid, &gid);
  if(ret) goto cleanup;

  /* Give permissions to sandbox directories */
  pathlen = strlen(s->overlay_path) + strlen("/merged") + 127 + 1;
  path = malloc(pathlen);
  if(!path) goto cleanup;

  const char *dirs[] = { "/merged", "/upper", "/work", "/", NULL };
  for(const char **p = dirs; *p != NULL; p++) {
    snprintf(path, pathlen, "%s%s", s->overlay_path, *p);
    ret = chown(path, uid, gid);
    if(ret) goto cleanup;
  }

  /* Clone WITHOUT CLONE_NEWUSER initially */
  child = clone(sandbox_entrypoint, stack_top,
      CLONE_NEWUSER |
      CLONE_NEWPID |
      CLONE_NEWNS |
      CLONE_NEWNET |
      CLONE_NEWUTS |
      CLONE_NEWIPC |
      CLONE_NEWCGROUP |
      SIGCHLD,
      &entrypoint_args);

  if (child < 0) goto cleanup;
  printf("[SANDBOX] running process %d\n", child);

  /* Parent closes child's end of socket */
  close(sockfd[1]);

  ret = setup_userns_mappings(child, uid, gid);
  if (ret) {
    send_msg(sockfd[0], MSG_PARENT_ERROR, errno);
    goto cleanup;
  }

  /* 6. Tell child mappings are done */
  if (send_msg(sockfd[0], MSG_PARENT_MAPPINGS_DONE, 0) < 0) {
    goto cleanup;
  }

  /* 1. Wait for child to be ready (initial setup) */
  if (recv_msg(sockfd[0], &msg) < 0) {
    fprintf(stderr, "[SANDBOX] failed to receive READY from child\n");
    goto cleanup;
  }

  if (msg.type == MSG_CHILD_ERROR) {
    fprintf(stderr, "[SANDBOX] child reported error: %s\n", strerror(msg.data));
    goto cleanup;
  }

  if (msg.type != MSG_CHILD_READY) {
    fprintf(stderr, "[SANDBOX] unexpected message from child: %d\n", msg.type);
    goto cleanup;
  }

  /* 2. Setup network, cgroup, eBPF */
  ret = setup_network(s, child);
  if (ret) {
    send_msg(sockfd[0], MSG_PARENT_ERROR, errno);
    goto cleanup;
  }

  ret = cgroup_create("uav-cgroup");
  if (ret) {
    send_msg(sockfd[0], MSG_PARENT_ERROR, errno);
    goto cleanup;
  }

  ret = cgroup_add_pid("uav-cgroup", child);
  if (ret) {
    send_msg(sockfd[0], MSG_PARENT_ERROR, errno);
    goto cleanup;
  }

  ret = cgroup_set_limits("uav-cgroup", &s->limits);
  if (ret) {
    send_msg(sockfd[0], MSG_PARENT_ERROR, errno);
    goto cleanup;
  }

  s->skel = sandbox_bpf__open();
  if (!s->skel) {
    send_msg(sockfd[0], MSG_PARENT_ERROR, errno);
    goto cleanup;
  }

  cgid = cgroup_getid("uav-cgroup");
  if (!cgid) {
    send_msg(sockfd[0], MSG_PARENT_ERROR, errno);
    goto cleanup;
  }

  s->skel->rodata->target_cgroup_id = cgid;

  ret = sandbox_bpf__load(s->skel);
  if (ret) {
    send_msg(sockfd[0], MSG_PARENT_ERROR, errno);
    goto cleanup;
  }

  ret = sandbox_bpf__attach(s->skel);
  if (ret) {
    send_msg(sockfd[0], MSG_PARENT_ERROR, errno);
    goto cleanup;
  }

  /* 3. Tell child to continue */
  if (send_msg(sockfd[0], MSG_PARENT_GO, 0) < 0) {
    goto cleanup;
  }

  /* 7. Wait for child to complete */
  if (recv_msg(sockfd[0], &msg) >= 0) {
    if (msg.type == MSG_CHILD_EXIT) {
      printf("[SANDBOX] child setup completed successfully\n");
    } else if (msg.type == MSG_CHILD_ERROR) {
      fprintf(stderr, "[SANDBOX] child final error: %s\n", strerror(msg.data));
      ret = 1;
    }
  }

  waitpid(child, &wstatus, 0);

  if (WIFEXITED(wstatus)) {
    const int es = WEXITSTATUS(wstatus);
    fprintf(stderr, "[SANDBOX] process exited status=%d\n", es);
    if(es != 0) ret = 1;
  } else if (WIFSIGNALED(wstatus)) {
    fprintf(stderr, "[SANDBOX] process killed by signal %d\n", WTERMSIG(wstatus));
  } else if (WIFSTOPPED(wstatus)) {
    fprintf(stderr, "[SANDBOX] process stopped by signal %d\n", WSTOPSIG(wstatus));
  }

  ret = 0;  /* Success if we got here */

cleanup:
  /* Cleanup logic */
  if (s->skel) {
    sandbox_bpf__destroy(s->skel);
    s->skel = NULL;
  }

  if (sockfd[0] != -1) close(sockfd[0]);
  if (sockfd[1] != -1) close(sockfd[1]);

  if (path) free(path);

  if (ret && child > 0) {
    kill(child, SIGKILL);
  }

  if(ret) {
    fprintf(stderr, "[SANDBOX] error during sandboxed execution: %s\n", strerror(errno));
  }

  return ret;
}

/* Destroy a sandbox by removing its filesystem tree */
void uav_sandbox_destroy(struct uav_sandbox *s) {
  int ret;
  size_t len;
  char *path = NULL;

  const char *dirs[] = {
    // "/merged/dev/pts",
    // "/merged/dev",
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
  char *newroot, *oldroot, *path = NULL, options[64];
  struct sandbox_entrypoint_args *args = args_;
  const struct uav_sandbox *s = args->s;
  int sockfd = args->comm_sock;
  const char *err_msg = NULL;
  struct sandbox_msg msg;

  size_t newroot_len = strlen(s->overlay_path) + strlen("/merged") + 1;
  size_t oldroot_len = strlen(s->overlay_path) + strlen("/merged") + strlen("/oldroot") + 1;
  size_t pathlen = strlen(s->overlay_path) + strlen("/merged/entrypoint.sh") + 1;

  newroot = malloc(newroot_len);
  oldroot = malloc(oldroot_len);
  path = malloc(pathlen);

  if(!newroot || !oldroot || !path) {
    send_msg(sockfd, MSG_CHILD_ERROR, ENOMEM);
    goto fail;
  }

  if (recv_msg(sockfd, &msg) < 0 || msg.type != MSG_PARENT_MAPPINGS_DONE) {
    err_msg = "failed to receive mappings done";
    goto fail;
  }

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

  /* Write entrypoint */
  snprintf(path, pathlen, "%s/merged/entrypoint.sh", s->overlay_path);
  ret = write_file_str(path, entrypoint);
  if(ret) goto fail;

  /* 1. Setup Mount Namespace */
  ret = mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL);
  if (ret < 0) {
    err_msg = "mount(/, MS_PRIVATE)";
    send_msg(sockfd, MSG_CHILD_ERROR, errno);
    goto fail;
  }

  /* 2. Prepare paths */
  snprintf(newroot, newroot_len, "%s/merged", s->overlay_path);
  snprintf(oldroot, oldroot_len, "%s/merged/oldroot", s->overlay_path);

  /* 3. Bind mount newroot */
  ret = mount(newroot, newroot, NULL, MS_BIND | MS_REC, NULL);
  if (ret < 0) {
    err_msg = "bind mount newroot";
    send_msg(sockfd, MSG_CHILD_ERROR, errno);
    goto fail;
  }

  /* 3. MOUNT PROC BEFORE PIVOT (The Fix) */
  // We mount the container's proc into the directory that WILL become /proc
  char proc_path[PATH_MAX];
  snprintf(proc_path, sizeof(proc_path), "%s/proc", newroot);

  mkdir(proc_path, 0555);
  // In rootless mode, the flags MS_NOSUID | MS_NOEXEC | MS_NODEV are often required
  ret = mount("proc", proc_path, "proc", MS_NOSUID | MS_NOEXEC | MS_NODEV, NULL);
  if (ret < 0) {
    err_msg = "pre-pivot mount proc";
    send_msg(sockfd, MSG_CHILD_ERROR, errno);
    goto fail;
  }

  /* 4. File operations before pivot */
  ret = sandbox_copyfile(s, args->hostprogram, "/malware.sh");
  if (ret != 0) {
    err_msg = "copy malware.sh";
    send_msg(sockfd, MSG_CHILD_ERROR, errno);
    goto fail;
  }

  ret = mkdir(oldroot, 0777);
  if (ret < 0 && errno != EEXIST) {
    err_msg = "mkdir oldroot";
    send_msg(sockfd, MSG_CHILD_ERROR, errno);
    goto fail;
  }
  /* 5. The Pivot */

  ret = syscall(SYS_pivot_root, newroot, oldroot);
  if (ret < 0) {
    err_msg = "pivot_root";
    send_msg(sockfd, MSG_CHILD_ERROR, errno);
    goto fail;
  }

  ret = chdir("/");
  if (ret < 0) {
    err_msg = "chdir(/)";
    send_msg(sockfd, MSG_CHILD_ERROR, errno);
    goto fail;
  }

  /* 6. Cleanup Host Links */
  ret = umount2("/oldroot", MNT_DETACH);
  if (ret < 0) {
    err_msg = "umount2(oldroot)";
    send_msg(sockfd, MSG_CHILD_ERROR, errno);
    goto fail;
  }

  ret = rmdir("/oldroot");
  if (ret < 0) {
    err_msg = "rmdir(oldroot)";
    send_msg(sockfd, MSG_CHILD_ERROR, errno);
    goto fail;
  }
  rmdir("/oldroot");

  snprintf(options, sizeof(options), "size=%zu", s->limits.tmpfs_size);
  mkdir("/tmp", 0755);
  ret = mount("tmpfs", "/tmp", "tmpfs", 0, options);
  if(ret) {
    err_msg = "mount /tmp";
    goto fail;
  }

  /* 14. Final setup */
  ret = sethostname(s->id, strlen(s->id));
  if(ret) {
    err_msg = "sethostname";
    goto fail;
  }

  mkdir("/etc", 0755);
  write_file_str("/etc/hostname", s->id);

  /* 8. Signal parent that we're ready for network/cgroup setup */
  if (send_msg(sockfd, MSG_CHILD_READY, 0) < 0) {
    goto fail;
  }

  /* 9. Wait for parent to finish network/cgroup setup */
  if (recv_msg(sockfd, &msg) < 0 || msg.type != MSG_PARENT_GO) {
    err_msg = "failed to receive GO from parent";
    goto fail;
  }

  /* 15. Clean up and exec */
  free(oldroot);
  free(newroot);

  /* Signal successful setup */
  send_msg(sockfd, MSG_CHILD_EXIT, 0);
  close(sockfd);

  /* 16. Execute as PID 1 */
  char *const argv[] = { "/bin/sh", "/entrypoint.sh", "/malware.sh", NULL };
  execv("/bin/sh", argv);
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

  /* Mount overlayfs from sandbox base */
  ret = create_overlayfs(s->root, s->overlay_path);
  if(ret) {
    fprintf(stderr, "[SANDBOX] cannot create overlayfs: %s\n", strerror(errno));
    return 1;
  }

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
    write(fd, "deny",4);
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

static int send_msg(int sockfd, enum sandbox_msg_type type, int data) {
  struct sandbox_msg msg = {
    .type = type,
    .data = data
  };

  ssize_t ret = send(sockfd, &msg, sizeof(msg), MSG_NOSIGNAL);
  if (ret != sizeof(msg)) {
    perror("send_msg failed");
    return -1;
  }
  return 0;
}

static int recv_msg(int sockfd, struct sandbox_msg *msg) {
  ssize_t ret = recv(sockfd, msg, sizeof(*msg), 0);
  if (ret != sizeof(*msg)) {
    perror("recv_msg failed");
    return -1;
  }
  return 0;
}
