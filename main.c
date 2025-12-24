#define _XOPEN_SOURCE 500
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <ftw.h>
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
#include <sys/wait.h>
#include <unistd.h>

#include <bpf/libbpf.h>
#include <openssl/evp.h>
#include <zip.h>

/* eBPF program */
#include "av.skel.h"

/* ======================================== Constants =========================================== */
static const char MB_SHA256_FILE [] = "data/av_sha256_signatures.txt";
static const char BUSYBOX_ZIP [] = "data/av_sandbox_busybox.zip";
static const char SANDBOX_ENTRYPOINT[] = "data/av_sandbox_entrypoint.sh";
static const char AV_SANDBOX_CGROUP_NAME[] = "av_sandbox";
static const char AV_SANDBOX_NETNS_NAME[] = "av_sandbox_netns";

/* =========================================== Types ============================================ */
#define SHA256_DIGEST_LEN 32
struct av_context {
  /* Each element of the array is a 32 byte digest */
  unsigned char (*signatures)[SHA256_DIGEST_LEN];
  size_t sigcount;
};

struct av_sandbox_limits {
  /* Maximum amount of memory that can be used by the sandbox (bytes)*/
  size_t memory_max;
  /* Maximum amount of CPU that can be used by the sandbox (% of a period) */
  size_t cpu_max;
  /* Maximum amount of pids (processes) into the sandbox */
  size_t pids_max;
};

/* Default limits */
static const struct av_sandbox_limits DEFAULT_LIMITS = {
  /* 128M */
  .memory_max = 1024 * 1024 * 128,
  /* 5% cpu */
  .cpu_max = 5000,
  /* 20 forks */
  .pids_max = 20,
};

struct av_sandbox {
  /* Path of the root filesystem tree */
  char root[256];

  /* Limits at creation time. This can be overridden when running programs */
  struct av_sandbox_limits limits;
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
static int cgroup_set_limits(const char *cgname, const struct av_sandbox_limits *limits) {
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
  int err;
  zip_t *za = zip_open(src, ZIP_RDONLY, &err);

  if (!za) {
    fprintf(stderr, "[SANDBOX] cannot open zip: error %d\n", err);
    return -1;
  }
 
  zip_int64_t num_entries = zip_get_num_entries(za, 0);
 
  for (zip_int64_t i = 0; i < num_entries; i++) {
    const char *name = zip_get_name(za, i, 0);
    if (!name) continue;
 
    char filepath[512];
    snprintf(filepath, sizeof(filepath), "%s/%s", output_path, name);
 
    struct zip_stat st;
    zip_stat_index(za, i, 0, &st);
 
    // Skip directories
    if (name[strlen(name) - 1] == '/') {
      mkdir(filepath, 0755);
      continue;
    }
 
    zip_file_t *zf = zip_fopen_index(za, i, 0);
    if (!zf) continue;
 
    FILE *f = fopen(filepath, "wb");
    if (!f) {
      zip_fclose(zf);
      continue;
    }
 
    char buf[8192];
    zip_int64_t nread;
    while ((nread = zip_fread(zf, buf, sizeof(buf))) > 0) {
      fwrite(buf, 1, nread, f);
    }
 
    fclose(f);
    zip_fclose(zf);
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

  if (rv) fprintf(stderr, "cannot remove %s: %s", fpath, strerror(errno));

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

/* Add IP address to interface */
static int add_ip_addr(int nlsock, const char *ifname, const char *ip, int prefix) {
  struct nl_addr_req req = {0};
  unsigned int ifindex = if_nametoindex(ifname);
  struct in_addr addr;
  struct in_addr bcast;
  uint32_t netmask = htonl(0xFFFFFFFF << (32 - prefix));

  if (ifindex == 0) return 1;

  if (inet_pton(AF_INET, ip, &addr) != 1) {
    fprintf(stderr, "[NETLINK] invalid IP: %s\n", ip);
    return 1;
  }
  bcast.s_addr = addr.s_addr | (~netmask);

  req.hdr.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifaddrmsg));
  req.hdr.nlmsg_type = RTM_NEWADDR;
  req.hdr.nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE | NLM_F_EXCL | NLM_F_ACK;
  req.ifa.ifa_family = AF_INET;
  req.ifa.ifa_prefixlen = prefix;
  req.ifa.ifa_index = ifindex;

  nl_add_attr(&req.hdr, sizeof(req), IFA_LOCAL, &addr, sizeof(addr));
  nl_add_attr(&req.hdr, sizeof(req), IFA_ADDRESS, &addr, sizeof(addr));
  nl_add_attr(&req.hdr, sizeof(req), IFA_BROADCAST, &bcast, sizeof(bcast));

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
static int add_default_route(int nlsock, const char *gw_ip, const char *ifname) {
  struct nl_route_req req = {0};
  struct in_addr gw;
  unsigned int ifindex = if_nametoindex(ifname);

  if (ifindex == 0) return 1;

  if (inet_pton(AF_INET, gw_ip, &gw) != 1) {
    fprintf(stderr, "[NETLINK] invalid gateway IP: %s\n", gw_ip);
    return 1;
  }

  req.hdr.nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));
  req.hdr.nlmsg_type = RTM_NEWROUTE;
  req.hdr.nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE | NLM_F_EXCL | NLM_F_ACK;
  req.rt.rtm_family = AF_INET;
  req.rt.rtm_table = RT_TABLE_MAIN;
  req.rt.rtm_protocol = RTPROT_BOOT;
  req.rt.rtm_scope = RT_SCOPE_UNIVERSE;
  req.rt.rtm_type = RTN_UNICAST;

  nl_add_attr(&req.hdr, sizeof(req), RTA_GATEWAY, &gw, sizeof(gw));
  nl_add_attr(&req.hdr, sizeof(req), RTA_OIF, &ifindex, sizeof(ifindex));

  return nl_send_and_recv(nlsock, &req.hdr);
}

/* ===================================== Sandbox ================================================ */
/* Create sandbox: extract zip directory in base root and copy entrypoint script. */
static int av_sandbox_create(struct av_sandbox *s, const char *sandbox_dir, const struct av_sandbox_limits *limits) {
  int ret;

  /* if limits is NULL use DEFAULT_LIMITS */
  const struct av_sandbox_limits *toapply = &DEFAULT_LIMITS;
  if(limits) {
    toapply = limits;
  }
  memcpy(&s->limits, toapply, sizeof(struct av_sandbox_limits));
  
  strncpy(s->root, sandbox_dir, sizeof(s->root) - 1);
  s->root[sizeof(s->root) - 1] = '\0';

  // // Create sandbox root directory
  // ret = mkdir(sandbox_dir, 0755);
  // if (ret != 0 && errno != EEXIST) {
  //   fprintf(stderr, "[SANDBOX] cannot create directory %s: %s\n", sandbox_dir, strerror(errno));
  //   return -1;
  // }
  //
  //
  // /* Extract busybox zip into sandbox root */
  // ret = extract_directory(BUSYBOX_ZIP, s->root);
  // if (ret != 0) {
  //   fprintf(stderr, "[SANDBOX] cannot extract base sandbox filesystem: %s\n", strerror(errno));
  //   rmtree(s->root);
  //   return -1;
  // }

  /* Copy entrypoint script */
  char entrypoint_dst[512];
  snprintf(entrypoint_dst, sizeof(entrypoint_dst), "%s/av_sandbox_entrypoint.sh", s->root);
  ret = copyfile(SANDBOX_ENTRYPOINT, entrypoint_dst);
  if (ret != 0) {
    fprintf(stderr, "[SANDBOX] cannot copy entrypoint: %s\n", strerror(errno));
    rmtree(s->root);
    return -1;
  }

  /* Make entrypoint executable */
  return chmod(entrypoint_dst, 0755);
}

static int create_netns(const char *netns) {
  int original_netnsfd, child_netnsfd, ret;
  const char netns_path[] = "/var/run/netns";
  char path[512];

  snprintf(path, sizeof(path), "%s/%s", netns_path, netns);

  original_netnsfd = open("/proc/self/ns/net", O_RDONLY);
  if (original_netnsfd < 0) return 1;

  ret = mkdir("/var/run/netns", 0755);

  /* netns already exists */
  if (ret != 0 && errno != EEXIST)
    return 1;
 
  // Remove if it already exists
  unlink(path);

  // Create a NEW network namespace by unsharing
  if (unshare(CLONE_NEWNET) < 0) return 1;

  // Now bind mount the current namespace to the file
  // First create an empty file
  child_netnsfd = open(path, O_RDONLY | O_CREAT | O_EXCL, 0444);
  if (child_netnsfd < 0) return 1;

  // Bind mount /proc/self/ns/net to that file
  if (mount("/proc/self/ns/net", path, "none", MS_BIND, NULL) < 0) {
    unlink(path);
    return 1;
  }

  setns(original_netnsfd, CLONE_NEWNET);
  close(child_netnsfd);
  close(original_netnsfd);

  return 0;
}

/* Set up a virtual ethernet pair. I need to create a veth pair to inspect all networking traffic
 * coming from the sandbox. This happens through netlink messages. The host-side can be configured 
 * immediately, but sandbox-side I need to move this process in the sandbox netns and configure the 
 * pair from there. This implies closing the current netlink socket (as it will be different under the 
 * other netns) and reopening to finish the configuration. The sandbox netns will have a peer veth 
 * with just a routing rule to send everything to the host side. */
static int av_sandbox_setup_network(const char *netns) {

  int ret, sockfd, original_netnsfd = -1, child_netnsfd = -1;
  struct sockaddr_nl sa = {0};
  const char netns_base_path[] = "/var/run/netns";
  char netns_path[512];
  const char veth1[] = "veth1";
  const char veth2[] = "veth2";
  const char veth1_ipv4[] = "10.10.10.1";
  const char veth2_ipv4[] = "10.10.10.2";
  int prefix = 30;

  snprintf(netns_path, sizeof(netns_path), "%s/%s", netns_base_path, netns);

  /* Open netlink socket */
  sockfd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);

  if (sockfd < 0) goto exit;

  sa.nl_family = AF_NETLINK;
  sa.nl_pid = 0;

  ret = bind(sockfd, (struct sockaddr *)&sa, sizeof(sa));
  if (ret < 0) goto exit;

  /* Create veth pair */
  ret = create_veth_pair(sockfd, veth1, veth2);
  if(ret) goto exit;

  /* Set host-side up */
  ret = set_link_up(sockfd, veth1);
  if(ret) goto exit;
  
  /* Set host-side up */
  ret = set_link_up(sockfd, veth2);
  if(ret) goto exit;

  /* Add an IP address to the host-side. Use just IPv4 for now */
  ret = add_ip_addr(sockfd, veth1, veth1_ipv4, prefix);
  if(ret) goto exit;

  /* Move sandbox-side into the netns */
  child_netnsfd = open(netns_path, O_RDONLY);
  if (child_netnsfd < 0) {
    ret = 1;
    goto exit;
  }

  ret = move_if_to_netns(sockfd, veth2, child_netnsfd);
  if(ret) goto exit;

  close(sockfd);

  /* Move ourselves into the sandbox-side netns, but save the current netns so we can come back */
  original_netnsfd = open("/proc/self/ns/net", O_RDONLY);
  if (original_netnsfd < 0) {
    ret = 1;
    goto exit;
  }

  ret = setns(child_netnsfd, CLONE_NEWNET);;
  if(ret < 0) goto exit;

  /* Reopen the socket */
  sockfd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);

  if (sockfd < 0) goto exit;

  sa.nl_family = AF_NETLINK;
  sa.nl_pid = 0;

  ret = bind(sockfd, (struct sockaddr *)&sa, sizeof(sa));
  if (ret < 0) goto exit;
  
  /* Set sandbox-side up */
  ret = set_link_up(sockfd, veth2);
  if(ret) goto exit;

  /* Add an IP address to the sandbox-side. Use just IPv4 for now */
  ret = add_ip_addr(sockfd, veth2, veth2_ipv4, prefix);
  if(ret) goto exit;

  /* Add default route towards host-side. */
  ret = add_default_route(sockfd, veth1_ipv4, veth2);
  if(ret) goto exit;

  /* Go back to original netns */
  ret = setns(original_netnsfd, CLONE_NEWNET);;
  if(ret < 0) goto exit;
  ret = 0;

exit:
  if (sockfd > 0) close(sockfd);
  if(child_netnsfd > 0 ) close(child_netnsfd);
  if(original_netnsfd > 0 ) close(original_netnsfd);
  if (ret != 0) fprintf(stderr, "[SANDBOX] cannot configure network: %s\n", strerror(errno));
  return ret;
}

/*
 * Prepare the sandbox before executing a process in it:
 * - move the process in a new cgroup and apply limits to it
 * - move the process in a new netns and forward all traffic to the host for inspection
 * - load and attach the eBPF program
 */
static int av_sandbox_prepare(const struct av_sandbox *s, const struct av_sandbox_limits *limits, pid_t pid, struct avbpf **skel) {

  int ret;
  unsigned long cgid;

  /* Create a new cgroup and apply limits */
  ret = create_cgroup(AV_SANDBOX_CGROUP_NAME);

  if(ret) {
    fprintf(stderr, "[SANDBOX] cannot create cgroup: %s\n", strerror(errno));
    return 1;
  }

  ret = cgroup_set_limits(AV_SANDBOX_CGROUP_NAME, &s->limits);
  if(ret) {
    fprintf(stderr, "[SANDBOX] cannot set limits: %s\n", strerror(errno));
    return 1;
  }

  /* Move the child in the new cgroup */
  ret = cgroup_add_pid(AV_SANDBOX_CGROUP_NAME, pid);
  if (ret) {
    fprintf(stderr, "[SANDBOX] cannot move child in cgroup %s\n", AV_SANDBOX_CGROUP_NAME);
    return 1;
  }

  /* Apply limits to the new cgroup fallback to default limits if current execution are not specified */
  const struct av_sandbox_limits *toapply = &s->limits;
  if(limits != NULL) toapply = limits;

  ret = cgroup_set_limits(AV_SANDBOX_CGROUP_NAME, toapply);

  if (ret) {
    fprintf(stderr, "[SANDBOX] cannot set limits to cgroup %s\n", AV_SANDBOX_CGROUP_NAME);
    return 1;
  }

  /* Create a new netns */
  ret = create_netns(AV_SANDBOX_NETNS_NAME);
  if(ret) {
    fprintf(stderr, "[SANDBOX] cannot create netns %s: %s\n", AV_SANDBOX_NETNS_NAME, strerror(errno));
    return 1;
  }

  /* Configure the sandbox networking */
  ret = av_sandbox_setup_network(AV_SANDBOX_NETNS_NAME);

  /* Setup forwarding */

  /* Move the child in a new pid namespace */

  /* Load and attach eBPF program */
  cgid = get_cgroup_id(AV_SANDBOX_CGROUP_NAME);
  if(cgid == 0) {
    fprintf(stderr, "[SANDBOX] cannot get cgroup id");
    return 1;
  }
  printf("[SANDBOX] running in cgroup %s (%lu)\n", AV_SANDBOX_CGROUP_NAME, cgid);

  /* Load eBPF program */
  *skel = avbpf__open();

  if(!skel) {
    fprintf(stderr, "[SANDBOX] cannot open BPF skeleton\n");
    return 1;
  }

  /* Initialize constants variables before loading */
  (*skel)->rodata->target_cgroup_id = cgid;

  ret = avbpf__load(*skel);
  if(ret) {
    fprintf(stderr, "[SANDBOX] cannot load ebpf program\n");
    return 1;
  }

  ret = avbpf__attach(*skel);
  if(ret) {
    fprintf(stderr, "[SANDBOX] cannot attach ebpf program\n");
    return 1;
  }

  printf("[SANDBOX] loaded and attached eBPF program successfully\n");
  return 0;
}

static int av_sandbox_run_program(const struct av_sandbox *s, const char *program, const struct av_sandbox_limits *limits) {
  int pipefd[2];
  struct avbpf *skel = NULL;
 
  /* Create a communication pipe for child and parent processes */
  if (pipe(pipefd) == -1) {
    fprintf(stderr, "[SANDBOX] cannot create pipe: %s", strerror(errno));
    close(pipefd[0]);
    close(pipefd[1]);
    goto cleanup;
  }

  pid_t pid = fork();
  switch(pid) {
    /* Fork error */
  case -1:
    fprintf(stderr, "[SANDBOX] cannot create process: %s", strerror(errno));
    goto cleanup;
    /* Child */
  case 0: {
      unshare(CLONE_NEWNS | CLONE_NEWNET);
      int ret = chroot(s->root);
      char buf;
      /* If cannot chroot exit */
      if(ret)  _exit(1);
      chdir("/");

      /* Close write-side of the pipe */
      ret = close(pipefd[1]);
      if(ret)  _exit(1);

      /* Wait to be moved in a new cgroup */
      ssize_t nread = read(pipefd[0], &buf, 1);

      assert(buf == 'X');
      assert(nread == 1);

      /* Close read-end of the pipe */
      ret = close(pipefd[0]);
      if(ret) _exit(1);

      /* Run the suspicious program in it */
      char * const argv[] = { "/bin/sh", "av_sandbox_entrypoint.sh", program, NULL };
      execv("/bin/sh", argv);

      _exit(EXIT_SUCCESS);
    }
    /* Parent */
  default: {
      char tosend = 'X';
      int wstatus, ret;

      /* Ignore read-end */
      ret = close(pipefd[0]);
      if (ret) {
        fprintf(stderr, "[SANDBOX] child cannot close pipe: %s\n", strerror(errno));
        kill(pid, SIGKILL);
      }

      /* Prepare sandbox for execution */
      ret = av_sandbox_prepare(s, limits, pid, &skel);

      if (ret) {
        fprintf(stderr, "[SANDBOX] aborting sandbox execution due to previous configuration error\n");
        kill(pid, SIGKILL);
      }

      /* Signal that the process can run (for now just send 'X') */
      write(pipefd[1], &tosend, 1);
      ret = close(pipefd[1]);

      if(ret) {
        fprintf(stderr, "[SANDBOX] parent cannot close pipe: %s\n", strerror(errno));
        kill(pid, SIGKILL);
      }

      /* Wait for the process to terminate */
      waitpid(pid, &wstatus, 0);
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
  }

cleanup:
  if(skel) avbpf__destroy(skel);

  return 0;
}

/* Copy a file from `src_path` in `dst_name` relative to sandbox */
static int av_sandbox_copy_file(const struct av_sandbox *s, const char *src_path, const char *dst_name) {
  char dst_path[512];
  int ret;
 
  // Copy to sandbox root
  snprintf(dst_path, sizeof(dst_path), "%s/%s", s->root, dst_name);
 
  ret = copyfile(src_path, dst_path);
  if (ret != 0) {
    fprintf(stderr, "[SANDBOX] cannot copy file to sandbox: %s\n", strerror(errno));
    return -1;
  }
 
  return 0;
}

/* Destroy a sandbox by removing its filesystem tree */
static void av_sandbox_destroy(const struct av_sandbox *s) {
  int ret;
  ret = rmtree(s->root);

  if (ret) fprintf(stderr, "[SANDBOX] cannot remove %s: %s\n", s->root, strerror(errno));
}

/* ===================================== Main functions ========================================== */

/* Initialize av_context struct */
// TODO: check configuration files signatures
static int av_init(struct av_context *ctx) {

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

/* Scan a single file */
static int av_scanfile(const struct av_context *ctx, const char *path, unsigned char *odigest, int *diglen) {
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

static void av_context_free(struct av_context *ctx) {
  if(ctx == NULL || ctx->signatures == NULL) return;

  free(ctx->signatures);
}

int main(void) {
  int ret;
  struct av_sandbox s;
  static struct av_context ctx = { 0 };
  const char path[] = "sample.sh";
  const char target_path[] = "/usr/bin/sample.sh";
  unsigned char digest[SHA256_DIGEST_LEN] = {0};
  char hexdigest[SHA256_DIGEST_LEN * 2 + 1] = {0};
  ssize_t digestlen, hexlen;

  ret = av_init(&ctx);

  if(ret) {
    fprintf(stderr, "cannot init av: (errno=%d) %s\nExiting.\n", errno, strerror(errno));
    exit(1);
  }

  printf("[AVINFO] Loaded %zu signatures\n", ctx.sigcount);

  /* Compute program digest*/
  FILE *f = fopen(path, "rb");
  assert(f);
  digestlen = calculate_sha256_from_file(f, digest);
  assert(digestlen == SHA256_DIGEST_LEN);
  fclose(f);

  /* Convert the program digest in hex */
  hexlen = digest_to_hex(digest, digestlen, hexdigest);
  assert(hexlen == SHA256_DIGEST_LEN * 2);
  hexdigest[hexlen] = 0;

  printf("[AVINFO] \"%s\" has signature: 0x%s\n", path, hexdigest);

  /* Execute the program in a sandbox for demonstration purposes */
  ret = av_sandbox_create(&s, "sandbox", NULL);
  if (ret != 0) {
    fprintf(stderr, "[SANDBOX] cannot create sandbox\n");
    goto exit;
  }

  /* Copy suspicious file in sandbox */
  ret = av_sandbox_copy_file(&s, path, target_path);
  if (ret != 0) {
    fprintf(stderr, "[SANDBOX] cannot copy \"%s\" in sandbox: %s\n", path, strerror(errno));
    goto exit;
  }

  /* Run the file in sandbox */
  ret = av_sandbox_run_program(&s, target_path, NULL);
  if (ret != 0) {
    fprintf(stderr, "[SANDBOX] cannot execute \"%s\" in sandbox: %s\n", target_path, strerror(errno));
    goto exit;
  }

exit:
  // av_sandbox_destroy(&s);
  av_context_free(&ctx);

  return 0;
}
