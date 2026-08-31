#ifndef UAV_PROTOCOL_H
#define UAV_PROTOCOL_H

#include <stddef.h>
#include <stdint.h>

#define UAV_PROTO_MAGIC 0x55415653u /* "UAVS" */
#define UAV_PROTO_VERSION 1
#define UAV_PROTO_MAX_PAYLOAD (64 * 1024)
#define UAV_PROTO_MAX_CHUNK (8 * 1024)

enum uav_msg_type {
  UAV_MSG_HELLO = 1,
  UAV_MSG_READY,
  UAV_MSG_STR,

  UAV_MSG_UPLOAD_BEGIN,
  UAV_MSG_UPLOAD_CHUNK,
  UAV_MSG_UPLOAD_END,

  UAV_MSG_RUN,
  UAV_MSG_KILL,
  UAV_MSG_EXIT,
  UAV_MSG_EVENT,
  UAV_MSG_ERROR
};

struct uav_proto_msg {
  uint32_t magic;
  uint16_t version;
  uint16_t type;
  uint32_t length;

  uint8_t payload[UAV_PROTO_MAX_PAYLOAD];
};

struct uav_transport;

int uav_proto_send(struct uav_transport* t, uint16_t type, const void* data,
                   uint32_t length);
int uav_proto_recv(struct uav_transport* t, struct uav_proto_msg* h);
int uav_proto_upload(struct uav_transport* t, char* path, size_t path_size,
                     const uint8_t* data, size_t size);
int uav_proto_download(struct uav_transport* t,
                       const struct uav_proto_msg* begin, const char* path,
                       uint8_t** data, size_t* size);

#endif  //! UAV_PROTOCOL_H
