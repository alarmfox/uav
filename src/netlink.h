#ifndef __UAV_NETLINK_K
#define __UAV_NETLINK_K

#include <netinet/in.h>

int create_veth_pair(int nlsock, const char *veth1, const char *veth2);
int set_link_up(int nlsock, const char *ifname);
int delete_link(int nlsock, const char *ifname);
int add_ip_addr(int nlsock, const char *ifname, const struct in_addr *addr, int prefix);
int move_if_to_netns(int nlsock, const char *ifname, int netns_fd);
int add_default_route(int nlsock, const struct in_addr *gw, const char *ifname);

#endif // !__UAV_NETLINK_K
