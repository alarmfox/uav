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
  UAV_SANDBOX_MSG_READY,
  UAV_SANDBOX_MSG_STR,

  UAV_SANDBOX_MSG_UPLOAD_BEGIN,
  UAV_SANDBOX_MSG_UPLOAD_CHUNK,
  UAV_SANDBOX_MSG_UPLOAD_END,

  UAV_SANDBOX_MSG_RUN,
  UAV_SANDBOX_MSG_KILL,
  UAV_SANDBOX_MSG_EXIT,
  UAV_SANDBOX_MSG_EVENT,
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
int uav_sandbox_proto_upload(int fd, char *path, size_t path_size,
    const uint8_t *data, size_t size);
int uav_sandbox_proto_download(int fd,
    const struct uav_sandbox_proto_msg *begin, const char *path,
    uint8_t **data, size_t *size);

#endif //! UAV_SANDBOX_PROTOCOL_H
