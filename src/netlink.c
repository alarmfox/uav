#include <arpa/inet.h>
#include <linux/stat.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/sockios.h>
#include <linux/veth.h>
#include <net/if.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "netlink.h"

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
int create_veth_pair(int nlsock, const char *veth1, const char *veth2) {
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
int set_link_up(int nlsock, const char *ifname) {
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
int delete_link(int nlsock, const char *ifname) {
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
int add_ip_addr(int nlsock, const char *ifname, const struct in_addr *addr, int prefix) {
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
int move_if_to_netns(int nlsock, const char *ifname, int netns_fd) {
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
int add_default_route(int nlsock, const struct in_addr *gw, const char *ifname) {
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
