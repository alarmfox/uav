#define _XOPEN_SOURCE 500
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <ftw.h>
#include <grp.h>
#include <linux/stat.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/sockios.h>
#include <linux/veth.h>
#include <net/if.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#include <bpf/libbpf.h>
#include <openssl/evp.h>
#include <zip.h>

/* eBPF program */
#include "uav.skel.h"

/* ======================================== Constants =========================================== */
static const char MB_SHA256_FILE [] = "data/uav_sha256_signatures.txt";
static const char BUSYBOX_ZIP [] = "data/uav_sandbox_busybox.zip";
static const char SANDBOX_ENTRYPOINT[] = "data/uav_sandbox_entrypoint.sh";

/* =========================================== Types ============================================ */
#define SHA256_DIGEST_LEN 32
#define MAX_PATH_LEN 256
struct uav_context {
  /* Each element of the array is a 32 byte digest */
  unsigned char (*signatures)[SHA256_DIGEST_LEN];
  size_t sigcount;
};

/* Limits that can be configured on a single sandbox  */
struct uav_sandbox_limits {
  /* Maximum amount of memory that can be used by the sandbox (bytes)*/
  size_t memory_max;
  /* Maximum amount of CPU that can be used by the sandbox (% of a period) */
  size_t cpu_max;
  /* Maximum amount of pids (processes) into the sandbox */
  size_t pids_max;
  /* Stack size*/
  size_t stack_size;
  /* Tmpfs size  */
  size_t tmpfs_size;
};

/* Default limits */
static const struct uav_sandbox_limits DEFAULT_LIMITS = {
  /* 128M */
  .memory_max = 1024 * 1024 * 128,
  /* 5% cpu */
  .cpu_max = 5000,
  /* 20 forks */
  .pids_max = 20,
  /* 1MB stack */
  .stack_size = 1024 * 1024,
  /* 16MB tmpfs */
  .tmpfs_size = 1024 * 1024 * 16,
};

/* Sandbox instance data. */
struct uav_sandbox {
  /* Identifier */
  char id[64];
  /* Path of the root filesystem tree */
  char root[MAX_PATH_LEN];
  /* Actual path where runtime data is stored. Overlayfs */
  char overlay_path[MAX_PATH_LEN];
  /* Name of the veth used by the host */
  char hostifname[IFNAMSIZ];
  /* Name of the veth used by the sandbox */
  char sandboxifname[IFNAMSIZ];
  /* IPv4 address of the host-side */
  struct in_addr hostip;
  /* IPv4 address of the sandbox-side */
  struct in_addr sandboxip;
  /* Prefix for the network */
  unsigned int prefix;
  /* Limits to be applied to the sandbox */
  struct uav_sandbox_limits limits;
  /* Reference to eBPF program */
  struct uavbpf *skel;
  /* Pointer to stack bottom: stack + limits.stack_size = stack_top */
  unsigned char *stack;
  /* Signal to extract */
  int initialized;
};

struct uav_sandbox_config {
  /* Actual path where runtime data is stored. Overlayfs */
  char overlay_path[MAX_PATH_LEN];
  /* Name of the veth used by the host */
  char hostifname[IFNAMSIZ];
  /* Name of the veth used by the sandbox */
  char sandboxifname[IFNAMSIZ];
  /* IPv4 address of the host-side */
  char hostip[64];
  /* IPv4 address of the sandbox-side */
  char sandboxip[64];
  /* Network prefix */
  unsigned int prefix;
};

struct uav_sandbox_entrypoint_args {
  /* Pointer to configured uav_sandbox */
  struct uav_sandbox *s;
  /* Path of the program to execute host-side */
  char hostprogram[MAX_PATH_LEN];
  /* Communication pipes */
  int pipe_ready[2];
  int pipe_go[2];
};

/* ====================================== Utils =================================================  */
/* Convert the current digest in a hex string. The hexstring must be null terminated by the caller */
static ssize_t digest_to_hex(const unsigned char *digest, int len, char *buf) {
  static const char hex[] = "0123456789abcdef";

  if(digest == NULL || buf == NULL) return -1;

  for (int i = 0; i < len; ++i) {
    buf[i * 2] = hex[digest[i] >> 4];
    buf[i * 2 + 1] = hex[digest[i] & 0xF];
  }

  return len * 2;
}

static inline int hexval(char c) {
  if (c >= '0' && c <= '9') return c - '0';
  else if (c >= 'a' && c <='f') return  c - 'a' + 10;
  else if (c >= 'A' && c <='F') return c - 'A' + 10; 

  /* If here, we are not parsing an hexadecimal value */
  assert(0);
}

/* Parses an hex digest and builds the original numeric digest value */
static ssize_t digest_from_hex(const char *buf, int len, unsigned char *digest) {

  if(!digest) return -1;

  assert(len % 2 == 0);
  for (int i = 0; i < len; i += 2) {
    int hi = hexval(buf[i]);
    int lo = hexval(buf[i + 1]);

    digest[i / 2] = (unsigned char) ((hi << 4) | lo);
  }

  return len / 2;
}

/* Compare 2 digests. This assumes that both digests have same length.
 * Returns 0 if they are the same (byte by byte) or the difference of the first non equal byte */
static int compare_digest(const unsigned char *a, const unsigned char *b, int len) {

  for(int i = 0; i < len; ++i) {
    if (a[i] != b[i]) return a[i] - b[i];
  }

  return 0;
}

/* Enable controllers in the parent cgroup so they're available to children */
static int enable_controllers(const char *parent_cgroup, const char *controllers) {
  char path[512];
  int fd, ret;

  /* Write to parent's subtree_control to enable controllers for children */
  snprintf(path, sizeof(path), "/sys/fs/cgroup/%s/cgroup.subtree_control", parent_cgroup);

  fd = open(path, O_WRONLY);
  if (fd < 0) {
    fprintf(stderr, "[SANDBOX] cannot open %s: %s\n", path, strerror(errno));
    return -1;
  }

  ret = write(fd, controllers, strlen(controllers));
  close(fd);

  if (ret < 0) {
    fprintf(stderr, "[SANDBOX] cannot enable controllers: %s\n", strerror(errno));
    return -1;
  }

  return 0;
}

/* Create a new cgroup in /sys/fs/cgroup (assume we have cgroup v2). This functions does not return 
 * an error if the cgroup alreay exists */
static int create_cgroup(const char *cgname) {
  char path[256];
  int ret;

  snprintf(path, sizeof(path), "/sys/fs/cgroup/%s", cgname);
  ret = mkdir(path, 0755);

  if (ret != 0 && errno != EEXIST) return ret;

  /* Enable controllers in ROOT cgroup for our child cgroup */
  /* Format: "+controller1 +controller2 +controller3" */
  ret = enable_controllers("", "+cpu +memory +pids +io");
  if (ret != 0) {
    fprintf(stderr, "[SANDBOX] cannot enable controllers in root\n");
    return ret;
  }

  return 0;
}

/* The kernel exposes the cgroup ID as stx_ino when querying a cgroup directory. */
static unsigned long get_cgroup_id(const char *cgname) {
  struct statx stx;
  char path[256];

  snprintf(path, sizeof(path), "/sys/fs/cgroup/%s", cgname);

  if (statx(AT_FDCWD, path, 0, STATX_INO, &stx) < 0) {
    perror("statx");
    return 0;
  }

  return stx.stx_ino;
}

/* Moves `pid` to cgroup `cgname`. Assume that the cgroup exists. */
static int cgroup_add_pid(const char *cgname, pid_t pid) {
  char path[256];
  int fd;
  char buf[32];

  snprintf(path, sizeof(path), "/sys/fs/cgroup/%s/cgroup.procs", cgname);

  fd = open(path, O_WRONLY);
  if (fd < 0) return -1;

  snprintf(buf, sizeof(buf), "%d", pid);
  write(fd, buf, strlen(buf));
  close(fd);
  return 0;
}

/* Set limits (memory, CPU and I/O) to the cgroup */
static int cgroup_set_limits(const char *cgname, const struct uav_sandbox_limits *limits) {
  char path[512];
  int fd, ret;
  char buf[64];

  /* Set memory limit */
  snprintf(path, sizeof(path), "/sys/fs/cgroup/%s/memory.max", cgname);
  fd = open(path, O_WRONLY);
  if (fd < 0) {
    fprintf(stderr, "[SANDBOX] cannot open %s: %s\n", path, strerror(errno));
    return -1;
  }

  snprintf(buf, sizeof(buf), "%zu", limits->memory_max);
  ret = write(fd, buf, strlen(buf));
  close(fd);
  if (ret < 0) return -1;

  /* Set CPU limit (cpu.max format: "$MAX $PERIOD") */
  snprintf(path, sizeof(path), "/sys/fs/cgroup/%s/cpu.max", cgname);
  fd = open(path, O_WRONLY);
  if (fd < 0) return -1;
  snprintf(buf, sizeof(buf), "%zu 100000", limits->cpu_max);
  ret = write(fd, buf, strlen(buf));
  close(fd);
  if (ret < 0) return -1;

  /* Set pid limit */
  snprintf(path, sizeof(path), "/sys/fs/cgroup/%s/pids.max", cgname);
  fd = open(path, O_WRONLY);
  if (fd < 0) return -1;
  snprintf(buf, sizeof(buf), "%zu", limits->pids_max);
  ret = write(fd, buf, strlen(buf));
  close(fd);
  if (ret < 0) return -1;

  return 0;
}

/* Extract src zip file in output directory */
static int extract_directory(const char *src, const char *output_path) {
  int ret;
  zip_t *za = zip_open(src, ZIP_RDONLY, &ret);
  zip_int64_t num_entries, nread;
  zip_uint8_t opsys;
  zip_uint32_t attributes;
  struct zip_stat st;
  zip_file_t *zf = NULL;
  FILE *f = NULL;
  char filepath[512], buf[8 * 1024];

  if (!za) {
    fprintf(stderr, "[SANDBOX] cannot open zip: error %d\n", ret);
    return -1;
  }

  num_entries = zip_get_num_entries(za, 0);

  for (zip_int64_t i = 0; i < num_entries; i++) {
    const char *name = zip_get_name(za, i, 0);
    if (!name) continue;

    snprintf(filepath, sizeof(filepath), "%s/%s", output_path, name);

    /* Get stat for the current file */
    zip_stat_index(za, i, 0, &st);

    /* Create directory */
    if (name[strlen(name) - 1] == '/') {
      mkdir(filepath, 0755);
      /* Skip to permission path */
      goto perm;
    }

    /* Open file in archive */
    zf = zip_fopen_index(za, i, 0);
    if (!zf) continue;

    /* Open destination file */
    f = fopen(filepath, "wb");
    if (!f) {
      zip_fclose(zf);
      continue;
    }

    /* Extract file byte by byte */
    while ((nread = zip_fread(zf, buf, sizeof(buf))) > 0) {
      fwrite(buf, 1, nread, f);
    }

    fclose(f);
    zip_fclose(zf);

perm:
    /* Retrieve permission and restore them */
    ret = zip_file_get_external_attributes(za, i, ZIP_FL_UNCHANGED, &opsys, &attributes);

    if(ret){
      fprintf(stderr, "[ZIP] cannot get permissions for %s\n", filepath);
      continue;
    }

    /* Check if permission were for UNIX */
    if (opsys == ZIP_OPSYS_UNIX ){
      /* Apply permissions with chmod */
      ret = chmod(filepath, attributes >> 16);
      if(ret) fprintf(stderr, "[ZIP] cannot set permissions on %s: %s\n", filepath, strerror(errno));

    } else {
      fprintf(stderr, "[ZIP] file was not compressed on Unix\n");
      exit(1);
    }
  }

  zip_close(za);
  return 0;
}

/* Computes SHA256 from a file */
static ssize_t calculate_sha256_from_file(FILE *file, unsigned char *digest) {

  if(!digest) return -1;

  int ret;
  EVP_MD_CTX *mdctx;
  unsigned char buf[8192];
  size_t nbytes;
  unsigned int digestlen;

  mdctx = EVP_MD_CTX_new();
  assert(mdctx);

  ret = EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL);
  assert(ret == 1);

  while ((nbytes = fread(buf, 1, sizeof(buf), file)), nbytes != 0) {
    ret = EVP_DigestUpdate(mdctx, buf, nbytes);
    assert(ret == 1);
  }

  ret = EVP_DigestFinal_ex(mdctx, digest, &digestlen);
  assert(ret == 1);
  assert(digestlen == SHA256_DIGEST_LEN);

  EVP_MD_CTX_free(mdctx);

  return digestlen;
}

static int unlink_cb(const char *fpath, const struct stat *sb, int typeflag, struct FTW *ftwbuf) {
  (void)sb;
  (void)typeflag;
  (void)ftwbuf;

  int rv = remove(fpath);

  if (rv) fprintf(stderr, "cannot remove %s: %s\n", fpath, strerror(errno));

  return rv;
}

/* Delete a directory recursively */
static int rmtree(const char *path) {
  return nftw(path, unlink_cb, 64, FTW_DEPTH | FTW_PHYS);
}

/* Copy file from src to dst. Perform a byte-byte copy */
static int copyfile(const char *src, const char *dst) {
  FILE *fsrc = NULL, *fdst = NULL;
  unsigned char buf[8192];
  size_t nread;

  fsrc = fopen(src, "rb");
  if (!fsrc) {
    fprintf(stderr, "[SANDBOX] cannot open source %s: %s\n", src, strerror(errno));
    return -1;
  }

  fdst = fopen(dst, "wb");
  if (!fdst) {
    fprintf(stderr, "[SANDBOX] cannot open destination %s: %s\n", dst, strerror(errno));
    fclose(fsrc);
    return -1;
  }

  while ((nread = fread(buf, 1, sizeof(buf), fsrc)) > 0) {
    if (fwrite(buf, 1, nread, fdst) != nread) {
      fprintf(stderr, "[SANDBOX] write error: %s\n", strerror(errno));
      goto cleanup;
    }
  }

  if (ferror(fsrc)) {
    fprintf(stderr, "[SANDBOX] read error: %s\n", strerror(errno));
    goto cleanup;
  }

cleanup:
  if (fsrc) fclose(fsrc);
  if (fdst) fclose(fdst);
  return 0;
}

/* Create runtime fs for the sandbox starting from `base`. This allows to easily spin up and destroy 
 * sandbox s. */
static int create_overlayfs(const char *base, const char *overlay_path) {
  int ret;
  char upper[MAX_PATH_LEN + 20], work[MAX_PATH_LEN + 20], merged[MAX_PATH_LEN + 20];

  snprintf(upper, sizeof(upper), "%s/upper", overlay_path);
  snprintf(work, sizeof(work), "%s/work", overlay_path);
  snprintf(merged, sizeof(merged), "%s/merged", overlay_path);

  ret = mkdir(upper, 0755);
  if(ret) return 1;
  ret = mkdir(work, 0755);
  if(ret) return 1;
  ret = mkdir(merged, 0755);
  if(ret) return 1;

  // Mount overlay: base (lower) + upper (changes) = merged (view)
  char opts[MAX_PATH_LEN * 3 + 128];
  snprintf(opts, sizeof(opts), "lowerdir=%s,upperdir=%s,workdir=%s", base, upper, work);

  return mount("overlay", merged, "overlay", 0, opts);
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
  char path[256];
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

/* ================================== Netlink utils ====================================== */
/* Netlink request structures */
struct nl_req {
  struct nlmsghdr hdr;
  struct ifinfomsg ifi;
  char attrbuf[512];
};

struct nl_addr_req {
  struct nlmsghdr hdr;
  struct ifaddrmsg ifa;
  char attrbuf[128];
};

struct nl_route_req {
  struct nlmsghdr hdr;
  struct rtmsg rt;
  char attrbuf[256];
};

/* Helper: add attribute to netlink message */
static void nl_add_attr(struct nlmsghdr *n, unsigned int maxlen, int type, const void *data, int alen) {
  int len = RTA_LENGTH(alen);
  struct rtattr *rta;

  if (NLMSG_ALIGN(n->nlmsg_len) + RTA_ALIGN(len) > maxlen) {
    fprintf(stderr, "[NETLINK] attribute overflow\n");
    exit(1);
    return;
  }

  rta = (struct rtattr*)(((char*)n) + NLMSG_ALIGN(n->nlmsg_len));
  rta->rta_type = type;
  rta->rta_len = len;
  memcpy(RTA_DATA(rta), data, alen);
  n->nlmsg_len = NLMSG_ALIGN(n->nlmsg_len) + RTA_ALIGN(len);
}

/* Send netlink message and wait for ACK */
static int nl_send_and_recv(int fd, struct nlmsghdr *n) {
  struct sockaddr_nl nladdr = {0};
  struct iovec iov = { n, n->nlmsg_len };
  struct msghdr msg = {
    .msg_name = &nladdr,
    .msg_namelen = sizeof(nladdr),
    .msg_iov = &iov,
    .msg_iovlen = 1,
  };

  nladdr.nl_family = AF_NETLINK;

  if (sendmsg(fd, &msg, 0) < 0) {
    perror("[NETLINK] sendmsg");
    return -1;
  }

  /* Receive ACK */
  char buf[4096];
  iov.iov_base = buf;
  iov.iov_len = sizeof(buf);

  int len = recvmsg(fd, &msg, 0);
  if (len < 0) {
    perror("[NETLINK] recvmsg");
    return -1;
  }

  struct nlmsghdr *h = (struct nlmsghdr*)buf;
  if (h->nlmsg_type == NLMSG_ERROR) {
    struct nlmsgerr *err = (struct nlmsgerr*)NLMSG_DATA(h);
    if (err->error != 0) {
      fprintf(stderr, "[NETLINK] error: %s\n", strerror(-err->error));
      return -1;
    }
  }

  return 0;
}

/* Create veth pair. The netlink message should have this structure:
 * IFLA_IFNAME = peer1
 * IFLA_LINKINFO
 *  IFLA_INFO_KIND = "veth"
 *  IFLA_INFO_DATA
 *    IFLA_VETH_INFO_PEER
 *      struct ifinfomsg
 *      IFLA_IFNAME = peer_name
 */
static int create_veth_pair(int nlsock, const char *veth1, const char *veth2) {
  struct nl_req req = {0};
  struct rtattr *linkinfo, *infodata, *peerinfo;
  struct ifinfomsg peer_ifi = {0};
  int initial_len;

  req.hdr.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg));
  req.hdr.nlmsg_type = RTM_NEWLINK;
  req.hdr.nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE | NLM_F_EXCL | NLM_F_ACK;
  req.ifi.ifi_family = AF_UNSPEC;
  req.ifi.ifi_index = 0;
  req.ifi.ifi_change = 0xFFFFFFFF;

  /* Add interface name (veth1) */
  nl_add_attr(&req.hdr, sizeof(req), IFLA_IFNAME, veth1, strlen(veth1));

  /* Start IFLA_LINKINFO */
  linkinfo = (struct rtattr *)(((char*)&req) + NLMSG_ALIGN(req.hdr.nlmsg_len));
  linkinfo->rta_type = IFLA_LINKINFO;
  linkinfo->rta_len = RTA_LENGTH(0);
  initial_len = req.hdr.nlmsg_len;
  req.hdr.nlmsg_len = NLMSG_ALIGN(req.hdr.nlmsg_len) + RTA_SPACE(0);

  /* Add IFLA_INFO_KIND = "veth" (nested inside IFLA_LINKINFO) */
  const char *kind = "veth";
  nl_add_attr(&req.hdr, sizeof(req), IFLA_INFO_KIND, kind, strlen(kind));

  /* Start IFLA_INFO_DATA (nested inside IFLA_LINKINFO) */
  infodata = (struct rtattr*)(((char*)&req) + NLMSG_ALIGN(req.hdr.nlmsg_len));
  infodata->rta_type = IFLA_INFO_DATA;
  infodata->rta_len = RTA_LENGTH(0);
  int infodata_start = req.hdr.nlmsg_len;
  req.hdr.nlmsg_len = NLMSG_ALIGN(req.hdr.nlmsg_len) + RTA_SPACE(0);

  /* Start VETH_INFO_PEER (nested inside IFLA_INFO_DATA) */
  peerinfo = (struct rtattr*)(((char*)&req) + NLMSG_ALIGN(req.hdr.nlmsg_len));
  peerinfo->rta_type = VETH_INFO_PEER;

  /* The VETH_INFO_PEER contains a struct ifinfomsg followed by attributes */
  int peer_start = req.hdr.nlmsg_len;

  /* Add the struct ifinfomsg for the peer */
  peer_ifi.ifi_family = AF_UNSPEC;
  peerinfo->rta_len = RTA_LENGTH(sizeof(struct ifinfomsg));
  req.hdr.nlmsg_len = NLMSG_ALIGN(req.hdr.nlmsg_len) + RTA_SPACE(sizeof(struct ifinfomsg));

  /* Copy the ifinfomsg into the attribute payload */
  memcpy(RTA_DATA(peerinfo), &peer_ifi, sizeof(peer_ifi));

  /* Add IFLA_IFNAME for peer (nested inside VETH_INFO_PEER, after ifinfomsg) */
  nl_add_attr(&req.hdr, sizeof(req), IFLA_IFNAME, veth2, strlen(veth2));

  /* Fix up VETH_INFO_PEER length */
  peerinfo->rta_len = req.hdr.nlmsg_len - peer_start;

  /* Fix up IFLA_INFO_DATA length */
  infodata->rta_len = req.hdr.nlmsg_len - infodata_start;

  /* Fix up IFLA_LINKINFO length */
  linkinfo->rta_len = req.hdr.nlmsg_len - initial_len;

  return nl_send_and_recv(nlsock, &req.hdr);
}

/* Set interface UP */
static int set_link_up(int nlsock, const char *ifname) {
  struct nl_req req = {0};
  unsigned int ifindex = if_nametoindex(ifname);

  if (ifindex == 0) return 1;

  req.hdr.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg));
  req.hdr.nlmsg_type = RTM_NEWLINK;
  req.hdr.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
  req.ifi.ifi_family = AF_UNSPEC;
  req.ifi.ifi_index = ifindex;
  req.ifi.ifi_flags = IFF_UP;
  req.ifi.ifi_change = IFF_UP;

  return nl_send_and_recv(nlsock, &req.hdr);
}

/* Delete an interface by name */
static int delete_link(int nlsock, const char *ifname) {
  struct nl_req req = {0};
  unsigned int ifindex = if_nametoindex(ifname);

  if (ifindex == 0) return 1;

  req.hdr.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg));
  req.hdr.nlmsg_type = RTM_DELLINK;
  req.hdr.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
  req.ifi.ifi_family = AF_UNSPEC;
  req.ifi.ifi_index = ifindex;

  return nl_send_and_recv(nlsock, &req.hdr);
}

/* Add IP address to interface */
static int add_ip_addr(int nlsock, const char *ifname, const struct in_addr *addr, int prefix) {
  struct nl_addr_req req = {0};
  unsigned int ifindex = if_nametoindex(ifname);
  struct in_addr bcast;
  uint32_t netmask = htonl(0xFFFFFFFF << (32 - prefix));

  if (ifindex == 0) return 1;

  bcast.s_addr = addr->s_addr | (~netmask);

  req.hdr.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifaddrmsg));
  req.hdr.nlmsg_type = RTM_NEWADDR;
  req.hdr.nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE | NLM_F_EXCL | NLM_F_ACK;
  req.ifa.ifa_family = AF_INET;
  req.ifa.ifa_prefixlen = prefix;
  req.ifa.ifa_index = ifindex;

  nl_add_attr(&req.hdr, sizeof(req), IFA_LOCAL, addr, sizeof(struct in_addr));
  nl_add_attr(&req.hdr, sizeof(req), IFA_ADDRESS, addr, sizeof(struct in_addr));
  nl_add_attr(&req.hdr, sizeof(req), IFA_BROADCAST, &bcast, sizeof(struct in_addr));

  return nl_send_and_recv(nlsock, &req.hdr);
}

/* Move interface to network namespace */
static int move_if_to_netns(int nlsock, const char *ifname, int netns_fd) {
  struct nl_req req = {0};
  unsigned int ifindex = if_nametoindex(ifname);

  if (ifindex == 0) return 1;

  req.hdr.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg));
  req.hdr.nlmsg_type = RTM_SETLINK;
  req.hdr.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
  req.ifi.ifi_family = AF_UNSPEC;
  req.ifi.ifi_index = ifindex;

  nl_add_attr(&req.hdr, sizeof(req), IFLA_NET_NS_FD, &netns_fd, sizeof(netns_fd));

  return nl_send_and_recv(nlsock, &req.hdr);
}

/* Add default route in namespace */
static int add_default_route(int nlsock, const struct in_addr *gw, const char *ifname) {
  struct nl_route_req req = {0};
  unsigned int ifindex = if_nametoindex(ifname);

  if (ifindex == 0) return 1;

  req.hdr.nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));
  req.hdr.nlmsg_type = RTM_NEWROUTE;
  req.hdr.nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE | NLM_F_EXCL | NLM_F_ACK;
  req.rt.rtm_family = AF_INET;
  req.rt.rtm_table = RT_TABLE_MAIN;
  req.rt.rtm_protocol = RTPROT_BOOT;
  req.rt.rtm_scope = RT_SCOPE_UNIVERSE;
  req.rt.rtm_type = RTN_UNICAST;

  nl_add_attr(&req.hdr, sizeof(req), RTA_GATEWAY, gw, sizeof(struct in_addr));
  nl_add_attr(&req.hdr, sizeof(req), RTA_OIF, &ifindex, sizeof(ifindex));

  return nl_send_and_recv(nlsock, &req.hdr);
}

/* ===================================== Sandbox ================================================ */
/* Create sandbox: extract zip directory in base root and copy entrypoint script. */
static int uav_sandbox_base_bootstrap(struct uav_sandbox *si, const char *sandbox_dir) {
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

  /* Copy entrypoint script */
  char entrypoint_dst[512];
  snprintf(entrypoint_dst, sizeof(entrypoint_dst), "%s/uav_sandbox_entrypoint.sh", si->root);
  ret = copyfile(SANDBOX_ENTRYPOINT, entrypoint_dst);
  if (ret != 0) {
    fprintf(stderr, "[SANDBOX] cannot copy entrypoint: %s\n", strerror(errno));
    rmtree(si->root);
    return -1;
  }

  si->initialized = 1;

  /* Make entrypoint executable */
  return chmod(entrypoint_dst, 0755);
}

/* Set up a virtual ethernet pair. We need to create a veth pair to inspect all networking traffic
 * coming from the sandbox. This happens through netlink messages. The host-side can be configured
 * immediately, but sandbox-side we need to move this process in the sandbox netns and configure the
 * pair from there. This implies closing the current netlink socket (as it will be different under the
 * other netns) and reopening to finish the configuration. The sandbox netns will have a peer veth
 * with just a routing rule to send everything to the host side. */
static int uav_sandbox_setup_network(struct uav_sandbox *s, pid_t child) {

  int ret = -1, nlsockfd = -1, original_netnsfd = -1, child_netnsfd = -1;
  struct sockaddr_nl sa = {0};
  char child_netns_path[512];

  /* Get child's network namespace fd */
  snprintf(child_netns_path, sizeof(child_netns_path), "/proc/%d/ns/net", child);
  child_netnsfd = open(child_netns_path, O_RDONLY);
  if (child_netnsfd < 0) {
    fprintf(stderr, "[PARENT] cannot open child netns: %s\n", strerror(errno));
    goto exit;
  }

  /* Save our original netns */
  original_netnsfd = open("/proc/self/ns/net", O_RDONLY);
  if (original_netnsfd < 0) {
    fprintf(stderr, "[PARENT] cannot open original netns: %s\n", strerror(errno));
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
static int uav_sandbox_setup_filesystem(const struct uav_sandbox *s) {
  int ret;
  char path[512], options[512];

  /* Mount overlayfs from sandbox base */
  ret = create_overlayfs(s->root, s->overlay_path);
  if(ret) {
    fprintf(stderr, "[SANDBOX] cannot create overlayfs: %s\n", strerror(errno));
    return 1;
  }

  /* Create /tmp and mount tmpfs */
  snprintf(path, sizeof(path), "%s/merged/tmp", s->overlay_path);
  ret = mkdir(path, 0755);
  if(ret) return 1;

  snprintf(options, sizeof(options), "size=%zu", s->limits.tmpfs_size);
  ret = mount("tmpfs", path, "tmpfs", 0, options);
  if(ret) return 1;

  /* Create /proc and mount procfs */
  snprintf(path, sizeof(path), "%s/merged/proc", s->overlay_path);
  ret = mkdir(path, 0755);
  if(ret) return 1;

  ret = mount("proc", path, "proc", MS_NOSUID | MS_NOEXEC | MS_NODEV, NULL);
  if(ret) return 1;

  /* Create /dev and mount it as a tmpfs*/
  snprintf(path, sizeof(path), "%s/merged/dev", s->overlay_path);
  ret = mkdir(path, 0755);
  if(ret) return 1;

  ret = mount("tmpfs", path, "tmpfs", MS_NOSUID | MS_NOEXEC, "mode=755");
  if(ret) return 1;

  /* Required device nodes */
  snprintf(path, sizeof(path), "%s/merged/dev/null", s->overlay_path);
  mknod(path, S_IFCHR | 0666, makedev(1, 3));

  snprintf(path, sizeof(path), "%s/merged/dev/zero", s->overlay_path);
  mknod(path, S_IFCHR | 0666, makedev(1, 5));

  snprintf(path, sizeof(path), "%s/merged/dev/tty", s->overlay_path);
  mknod(path, S_IFCHR | 0666, makedev(5, 0));

  /* /dev/pts */
  snprintf(path, sizeof(path), "%s/merged/dev/pts", s->overlay_path);
  mkdir(path, 0755);

  ret = mount("devpts", path, "devpts", 0,
      "newinstance,ptmxmode=0666,mode=620");
  if (ret) return 1;

  /* /dev/ptmx */
  snprintf(path, sizeof(path), "%s/merged/dev/ptmx", s->overlay_path);
  return symlink("/dev/pts/ptmx", path);

}

/* Copy a file from `src_path` in `dst_name` (preserving permissions) relative to sandbox */
static int uav_sandbox_copy_file(const struct uav_sandbox *si, const char *src_path, const char *dst_name) {
  char dst_path[512];
  struct stat statbuf;
  int ret;

  snprintf(dst_path, sizeof(dst_path), "%s/merged/%s", si->overlay_path, dst_name);

  /* Copy file into sandbox */
  ret = copyfile(src_path, dst_path);
  if (ret != 0) {
    fprintf(stderr, "[SANDBOX] cannot copy file to sandbox: %s\n", strerror(errno));
    return 1;
  }

  /* Get permissions */
  ret = stat(src_path, &statbuf);
  if (ret != 0) {
    fprintf(stderr, "[SANDBOX] cannot stat file: %s\n", strerror(errno));
    return 1;
  }

  /* Apply permissions to copied file */
  ret = chmod(dst_path,  statbuf.st_mode);
  if (ret != 0) {
    fprintf(stderr, "[SANDBOX] cannot chmod file: %s\n", strerror(errno));
    return 1;
  }

  return 0;
}

/* Configure sandbox with runtime data. This includes overlayfs path, IPv4 addresses. This function
 * does not perform any action apart creating the overlayfs directory, but populates structure for
 * later use */
static int uav_sandbox_configure(struct uav_sandbox *s, const struct uav_sandbox_limits *limits, const struct uav_sandbox_config *config) {
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
  const struct uav_sandbox_limits *toapply = &DEFAULT_LIMITS;
  if(limits) toapply = limits;
  memcpy(&s->limits, toapply, sizeof(struct uav_sandbox_limits));

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
  strncpy(s->hostifname, config->hostifname, strlen(config->hostifname) + 1);
  strncpy(s->sandboxifname, config->sandboxifname, strlen(config->sandboxifname) + 1);

  /* Save prefix */
  s->prefix = config->prefix;

  return 0;
}

/* Entrypoint process for sandbox. This should PID 1 for this namespace. The entrypoint coordinates
 * with parent for networking and some configuration (ie. attach the eBPF to the specific process).
 * The function uses private mount /, pivot_root to create a fully isolated process.
 * */
static int uav_sandbox_entrypoint(void *args_) {
  int ret;
  char c;
  char newroot[MAX_PATH_LEN + 64], oldroot[MAX_PATH_LEN + 64];
  struct uav_sandbox_entrypoint_args *args = args_;
  const struct uav_sandbox *s = args->s;
  int *pipe_ready = args->pipe_ready;
  int *pipe_go = args->pipe_go;
  const char *err_msg = NULL;

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
  snprintf(newroot, sizeof(newroot), "%s/merged", s->overlay_path);
  snprintf(oldroot, sizeof(oldroot), "%s/merged/oldroot", s->overlay_path);

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
  ret = uav_sandbox_copy_file(s, args->hostprogram, "/malware.sh");
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

  /* 8. Execute */
  char *const argv[] = { "/bin/sh", "/uav_sandbox_entrypoint.sh", "/malware.sh", NULL };
  execv("/bin/sh", argv);

  /* Execv only returns on error */
  err_msg = "execv";

fail:
  if (err_msg) {
    fprintf(stderr, "[SANDBOX] cannot start process %s: %s\n", err_msg, strerror(errno));
  }
  _exit(1);
}

/* Execute a program in the sandbox. This includes spawning a new process and attaching the ebpf program */
static int uav_sandbox_run_program(struct uav_sandbox *s, const char *program) {
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
  char path[MAX_PATH_LEN];
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
  strncpy(args->hostprogram, program, sizeof(args->hostprogram) - 1);

  /* Create the overlayfs for this instance. */
  ret = uav_sandbox_setup_filesystem(s);
  if(ret) goto cleanup;

  /* Give permission to sandbox folders */
  ret = get_realuid(&uid, &gid);
  if(ret) goto cleanup;

  printf("[SANDBOX] Mapping root to uid=%u gid=%u\n", uid, gid);

  const char *dirs[] = {
    "/merged",
    "/upper",
    "/work",
    "/",
    NULL
  };

  for(const char **p = dirs; *p != NULL; p++) {
    snprintf(path, sizeof(path), "%s%s", s->overlay_path, *p);
    ret = chown(path, uid, gid);
    if(ret) goto cleanup;
  }

  /* Clone */
  child = clone(uav_sandbox_entrypoint, stack_top,
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
  ret = uav_sandbox_setup_network(s, child);
  if (ret) goto cleanup;

  /* Cgroup */
  ret = create_cgroup("uav-cgroup");
  if (ret) goto cleanup;

  ret = cgroup_add_pid("uav-cgroup", child);
  if (ret) goto cleanup;

  ret = cgroup_set_limits("uav-cgroup", &s->limits);
  if (ret) goto cleanup;

  /* eBPF */
  s->skel = uavbpf__open();
  if (!s->skel) goto cleanup;

  cgid = get_cgroup_id("uav-cgroup");
  if (!cgid) goto cleanup;

  s->skel->rodata->target_cgroup_id = cgid;

  ret = uavbpf__load(s->skel);
  if (ret) goto cleanup;

  ret = uavbpf__attach(s->skel);
  if (ret) goto cleanup;

  ret = setup_userns_mappings(child, uid, gid);
  if (ret) goto cleanup;

  /* Allow child to run */
  c = 'X';
  ret = 0;

  printf("[SANDBOX] running process %d\n", child);

cleanup:
  /* Notify child */
  if (pipe_go[1] != -1) {
    write(pipe_go[1], &c, 1);
    close(pipe_go[1]);
  }

  /* Wait for child to exit */
  if (child > 0) {
    waitpid(child, &wstatus, 0);

    if (WIFEXITED(wstatus)) {
      fprintf(stderr, "[SANDBOX] process exited status=%d\n", WEXITSTATUS(wstatus));
    } else if (WIFSIGNALED(wstatus)) {
      fprintf(stderr, "[SANDBOX] process killed by signal %d\n", WTERMSIG(wstatus));
    } else if (WIFSTOPPED(wstatus)) {
      fprintf(stderr, "[SANDBOX] process stopped by signal %d\n", WSTOPSIG(wstatus));
    } else if (WIFCONTINUED(wstatus)) {
      fprintf(stderr,"[SANDBOX] process continued\n");
    }

  }

  if (s->skel) {
    uavbpf__destroy(s->skel);
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
static void uav_sandbox_destroy(struct uav_sandbox *s) {
  int ret;
  char path[MAX_PATH_LEN + 64];

  const char *dirs[] = {
    "/merged/dev/pts",
    "/merged/tmp",
    "/merged/proc",
    "/merged/dev",
    "/merged",
    NULL
  };

  for(const char **p = dirs; *p != NULL; p++) {
    snprintf(path, sizeof(path), "%s%s", s->overlay_path, *p);
    ret = umount2(path, MNT_FORCE);
    if(ret) fprintf(stderr, "[SANDBOX] cannot unmount %s: %s\n", path, strerror(errno)); 
  }
 
  /* Remove tree */
  ret = rmtree(s->overlay_path);
  if(ret) fprintf(stderr, "[SANDBOX] cannot remove tree at %s: %s\n", s->overlay_path, strerror(errno));

  /* Remove the stack */
  if(s->stack) free(s->stack);
  s->stack = NULL;
}

/* ===================================== Main functions ========================================== */

/* Initialize av_context struct */
// TODO: check configuration files signatures
static int av_init(struct uav_context *ctx) {

  /*
   * Format:
   * - preamble
   * - signatures
   * - number of signatures:  # Number of entries: 1015158\r\n
   */

  char size[32];
  char c; 
  int n = 0;
  long pos = 0;
  FILE* file = fopen(MB_SHA256_FILE, "r");

  if(!file) return 1;

  /* Jump to the end of file */
  fseek(file, 0L, SEEK_END);

  /* Skip '\r\n' */
  fseek(file, -2, SEEK_CUR);

  /* Read the number of entries backwards */
  pos = ftell(file);

  do {
    fseek(file, pos--, SEEK_SET);
    c = fgetc(file);
    size[n++] = c; 
  } while(pos >= 0 && c != ' ');
  size[n] = 0;

  // Put in correct byte order for atol
  for(int i = 0; i < n/2; ++i) {
    char tmp = size[i];

    /* Swap with other half array */
    size[i] = size[n - i -1];
    size[n - i - 1] = tmp;
  }

  ctx->sigcount = atol(size);
  ctx->signatures = malloc(sizeof(*ctx->signatures) * ctx->sigcount);

  /* Go back to first entry */
  fseek(file, 0, SEEK_SET);

  /* Skip all lines beginning with '#' */
  char line[128];
  size_t i = 0;
  while(fgets(line, 128, file) != NULL && i < ctx->sigcount) {
    if (line[0] == '#') continue;
    ssize_t k = digest_from_hex(line, SHA256_DIGEST_LEN * 2, ctx->signatures[i]);
    assert(k == SHA256_DIGEST_LEN);
    i += 1;
  }

  fclose(file);
  return 0;
}

/* Scan a single file. Compute its hash and compare against signature lists */
static int av_scanfile(const struct uav_context *ctx, const char *path, unsigned char *odigest, int *diglen) {
  ssize_t len;
  unsigned char digest[256];
  int ismalware = 0;
  FILE *file = fopen(path, "rb");
  assert(file);

  len = calculate_sha256_from_file(file, digest);
  fclose(file);

  assert(digest);
  assert(len == SHA256_DIGEST_LEN);

  for(size_t i = 0; i < ctx->sigcount && !ismalware; ++i) {
    if(compare_digest(digest, ctx->signatures[i], SHA256_DIGEST_LEN) == 0) ismalware = 1;
  }

  /* Save file digest in odigest */
  memcpy(odigest, digest, SHA256_DIGEST_LEN);
  if(diglen) *diglen = SHA256_DIGEST_LEN;

  return ismalware;
}

static void av_context_free(struct uav_context *ctx) {
  if(ctx == NULL || ctx->signatures == NULL) return;

  free(ctx->signatures);
}

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
