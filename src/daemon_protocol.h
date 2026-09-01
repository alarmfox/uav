#ifndef UAV_DAEMON_PROTOCOL_H
#define UAV_DAEMON_PROTOCOL_H

#include <stdint.h>

#include "protocol_utils.h"

#define UAV_DAEMON_PROTO_MAGIC 0x55415644u /* "UAVD" */
#define UAV_DAEMON_PROTO_VERSION 1

enum uav_daemon_proto_msg_type {
  UAV_DAEMON_MSG_HELLO = 1,
  UAV_DAEMON_MSG_ATTACH_SELF,
  UAV_DAEMON_MSG_ERROR
};

struct uav_transport;

int uav_daemon_proto_send(struct uav_transport* transport, uint16_t type,
                          const void* payload, uint32_t length);
int uav_daemon_proto_recv(struct uav_transport* transport,
                          struct uav_proto_msg* msg);

#endif  // !UAV_DAEMON_PROTOCOL_H
