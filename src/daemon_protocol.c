#include "daemon_protocol.h"

#include <errno.h>

int uav_daemon_proto_send_request(int fd, uint16_t type, const void* payload,
                                  uint32_t length) {
  return uav_proto_seqpacket_send(fd, UAV_DAEMON_PROTO_MAGIC,
                                  UAV_DAEMON_PROTO_VERSION, UAV_PROTO_REQUEST,
                                  type, 0, payload, length);
}

int uav_daemon_proto_receive_request(int fd, struct uav_proto_msg* msg,
                                     struct ucred* credentials) {
  if (credentials == NULL) {
    errno = EINVAL;
    return -1;
  }

  return uav_proto_seqpacket_receive(
      fd, UAV_DAEMON_PROTO_MAGIC, UAV_DAEMON_PROTO_VERSION, UAV_PROTO_REQUEST,
      msg, credentials);
}

int uav_daemon_proto_send_response(int fd, uint16_t request_type, int error,
                                   const void* body, uint32_t body_length) {
  return uav_proto_seqpacket_send(
      fd, UAV_DAEMON_PROTO_MAGIC, UAV_DAEMON_PROTO_VERSION, UAV_PROTO_RESPONSE,
      request_type, error, body, body_length);
}

int uav_daemon_proto_receive_response(int fd, uint16_t request_type,
                                      struct uav_proto_msg* msg) {
  if (uav_proto_seqpacket_receive(fd, UAV_DAEMON_PROTO_MAGIC,
                                  UAV_DAEMON_PROTO_VERSION,
                                  UAV_PROTO_RESPONSE, msg, NULL) < 0)
    return -1;
  if (msg->type != request_type) {
    errno = EPROTO;
    return -1;
  }
  return 0;
}
