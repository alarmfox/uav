#include "daemon_protocol.h"

#include "protocol_utils.h"

int uav_daemon_proto_send(struct uav_transport* transport, uint16_t type,
                          const void* payload, uint32_t length) {
  return uav_proto_send_frame(transport, UAV_DAEMON_PROTO_MAGIC,
                              UAV_DAEMON_PROTO_VERSION, type, payload, length);
}

int uav_daemon_proto_recv(struct uav_transport* transport,
                          struct uav_proto_msg* msg) {
  return uav_proto_recv_frame(transport, UAV_DAEMON_PROTO_MAGIC,
                              UAV_DAEMON_PROTO_VERSION, msg);
}
