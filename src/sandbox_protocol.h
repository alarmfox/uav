#ifndef UAV_SANDBOX_PROTOCOL_H
#define UAV_SANDBOX_PROTOCOL_H

#include <stdint.h>

#define UAV_SANDBOX_PROTO_MAGIC   0x55415653u /* "UAVS" */
#define UAV_SANDBOX_PROTO_VERSION 1
#define UAV_SANDBOX_PROTO_MAX_PAYLOAD (64 * 1024)

enum uav_sandbox_msg_type {
  UAV_SANDBOX_MSG_HELLO = 1,
  UAV_SANDBOX_MSG_CONFIG_DONE,
  UAV_SANDBOX_MSG_READY,
  UAV_SANDBOX_MSG_RUN,
  UAV_SANDBOX_MSG_KILL,
  UAV_SANDBOX_MSG_EXIT,
  UAV_SANDBOX_MSG_ERROR
};

struct uav_sandbox_proto_msg {
  uint32_t magic;
  uint16_t version;
  uint16_t type;
  uint32_t length;

  uint8_t payload[UAV_SANDBOX_PROTO_MAX_PAYLOAD];
};

int uav_sandbox_proto_send(int fd, uint16_t type, const void *data, uint32_t length);
int uav_sandbox_proto_recv(int fd, struct uav_sandbox_proto_msg *h);

#endif //! UAV_SANDBOX_PROTOCOL_H
