#ifndef UAV_SANDBOX_PROTOCOL_H
#define UAV_SANDBOX_PROTOCOL_H

#include <stdint.h>
#include <stddef.h>

#define UAV_SANDBOX_PROTO_MAGIC   0x55415653u /* "UAVS" */
#define UAV_SANDBOX_PROTO_VERSION 1
#define UAV_SANDBOX_PROTO_MAX_PAYLOAD (64 * 1024)
#define UAV_SANDBOX_PROTO_MAX_CHUNK (8 * 1024)

enum uav_sandbox_msg_type {
  UAV_SANDBOX_MSG_HELLO = 1,
  UAV_SANDBOX_MSG_READY = 2,

  UAV_SANDBOX_MSG_UPLOAD_BEGIN = 3,
  UAV_SANDBOX_MSG_UPLOAD_CHUNK = 4,
  UAV_SANDBOX_MSG_UPLOAD_END = 5,

  UAV_SANDBOX_MSG_RUN = 6,
  UAV_SANDBOX_MSG_KILL = 7,
  UAV_SANDBOX_MSG_EXIT = 8,
  UAV_SANDBOX_MSG_EVENT = 9,
  UAV_SANDBOX_MSG_ERROR = 10
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
int uav_sandbox_proto_upload(int fd, const uint8_t *data, size_t size);
int uav_sandbox_proto_download(int fd, uint8_t **data, size_t *size);

#endif //! UAV_SANDBOX_PROTOCOL_H
