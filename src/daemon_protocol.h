#ifndef UAV_DAEMON_PROTOCOL_H
#define UAV_DAEMON_PROTOCOL_H

#include <stdint.h>

#include "protocol_utils.h"

#define UAV_DAEMON_PROTO_MAGIC 0x55415644u /* "UAVD" */
#define UAV_DAEMON_PROTO_VERSION 3

enum uav_daemon_proto_msg_type {
  UAV_DAEMON_MSG_REGISTER_AGENT = 1,
  UAV_DAEMON_MSG_REGISTER_WORKLOAD,
};

struct uav_transport;

int uav_daemon_proto_send_request(struct uav_transport* transport,
                                  uint16_t type, const void* payload,
                                  uint32_t length);
int uav_daemon_proto_send_response(struct uav_transport* transport,
                                   uint16_t request_type, int error,
                                   const void* body, uint32_t body_length);
int uav_daemon_proto_recv(struct uav_transport* transport,
                          struct uav_proto_msg* msg);
int uav_daemon_proto_decode_response(const struct uav_proto_msg* msg,
                                     uint16_t request_type, int* error,
                                     const uint8_t** body,
                                     uint32_t* body_length);

#endif  // !UAV_DAEMON_PROTOCOL_H
