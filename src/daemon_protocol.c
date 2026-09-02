#include "daemon_protocol.h"

#include <errno.h>

#include "protocol_utils.h"

static int uav_daemon_proto_register(struct uav_transport* transport,
                                     uint16_t type);

int uav_daemon_proto_send_request(struct uav_transport* transport,
                                  uint16_t type, const void* payload,
                                  uint32_t length) {
  return uav_proto_send_request(transport, UAV_DAEMON_PROTO_MAGIC,
                                UAV_DAEMON_PROTO_VERSION, type, payload,
                                length);
}

int uav_daemon_proto_send_response(struct uav_transport* transport,
                                   uint16_t request_type, int error,
                                   const void* body, uint32_t body_length) {
  return uav_proto_send_response(transport, UAV_DAEMON_PROTO_MAGIC,
                                 UAV_DAEMON_PROTO_VERSION, request_type, error,
                                 body, body_length);
}

int uav_daemon_proto_recv(struct uav_transport* transport,
                          struct uav_proto_msg* msg) {
  return uav_proto_recv_frame(transport, UAV_DAEMON_PROTO_MAGIC,
                              UAV_DAEMON_PROTO_VERSION, msg);
}

int uav_daemon_proto_decode_response(const struct uav_proto_msg* msg,
                                     uint16_t request_type, int* error,
                                     const uint8_t** body,
                                     uint32_t* body_length) {
  return uav_proto_decode_response(msg, request_type, error, body, body_length);
}

static int uav_daemon_proto_register(struct uav_transport* transport,
                                     uint16_t type) {
  const uint8_t* body;
  uint32_t body_length;
  struct uav_proto_msg msg;
  int remote_error;

  if (uav_daemon_proto_send_request(transport, type, NULL, 0) < 0) return -1;
  if (uav_daemon_proto_recv(transport, &msg) < 0) return -1;
  if (uav_daemon_proto_decode_response(&msg, type, &remote_error, &body,
                                       &body_length) < 0)
    return -1;

  if (body_length != 0) {
    errno = EPROTO;
    return -1;
  }

  if (remote_error != 0) {
    errno = remote_error;
    return -1;
  }

  return 0;
}

int uav_daemon_proto_register_agent(struct uav_transport* transport) {
  return uav_daemon_proto_register(transport, UAV_DAEMON_MSG_REGISTER_AGENT);
}

int uav_daemon_proto_register_workload(struct uav_transport* transport) {
  return uav_daemon_proto_register(transport,
                                   UAV_DAEMON_MSG_REGISTER_WORKLOAD);
}
