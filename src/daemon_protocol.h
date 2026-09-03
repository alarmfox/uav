#ifndef UAV_DAEMON_PROTOCOL_H
#define UAV_DAEMON_PROTOCOL_H

#include <stdint.h>

#include "protocol_utils.h"

#define UAV_DAEMON_PROTO_MAGIC 0x55415644u /* "UAVD" */
#define UAV_DAEMON_PROTO_VERSION 4

enum uav_daemon_proto_msg_type {
  UAV_DAEMON_MSG_REGISTER_AGENT = 1,
  UAV_DAEMON_MSG_REGISTER_WORKLOAD,
};

int uav_daemon_proto_send_request(int fd, uint16_t type, const void* payload,
                                  uint32_t length);
int uav_daemon_proto_receive_request(int fd, struct uav_proto_msg* msg,
                                     struct ucred* credentials);
int uav_daemon_proto_send_response(int fd, uint16_t request_type, int error,
                                   const void* body, uint32_t body_length);
int uav_daemon_proto_receive_response(int fd, uint16_t request_type,
                                      struct uav_proto_msg* msg);

#endif  // !UAV_DAEMON_PROTOCOL_H
