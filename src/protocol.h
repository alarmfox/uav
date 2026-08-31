#ifndef UAV_PROTOCOL_H
#define UAV_PROTOCOL_H

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
  UAV_MSG_UPLOAD_ACCEPT,
  UAV_MSG_UPLOAD_CHUNK,
  UAV_MSG_UPLOAD_END,
  UAV_MSG_UPLOAD_DONE,

  UAV_MSG_RUN,
  UAV_MSG_KILL,
  UAV_MSG_EXIT,
  UAV_MSG_EVENT,
  UAV_MSG_ERROR
};

struct uav_proto_msg {
  uint16_t type;
  uint32_t length;
  uint8_t payload[UAV_PROTO_MAX_PAYLOAD];
};

enum uav_upload_purpose {
  UAV_UPLOAD_DATA = 1,
  UAV_UPLOAD_EXECUTABLE,
};

/* Host-order values. protocol.c owns their wire representation. */
struct uav_upload_meta {
  uint32_t size;
  uint32_t source_mode;
  enum uav_upload_purpose purpose;
};

struct uav_transport;

int uav_proto_send(struct uav_transport* transport, uint16_t type,
                   const void* data, uint32_t length);
int uav_proto_recv(struct uav_transport* transport, struct uav_proto_msg* msg);

int uav_proto_upload(struct uav_transport* transport, int source_fd,
                     const struct uav_upload_meta* meta);
int uav_proto_decode_upload_begin(const struct uav_proto_msg* msg,
                                  struct uav_upload_meta* meta);
int uav_proto_accept_upload(struct uav_transport* transport);
int uav_proto_receive_upload(struct uav_transport* transport,
                             int destination_fd, uint32_t size);
int uav_proto_complete_upload(struct uav_transport* transport);

int uav_proto_send_exit(struct uav_transport* transport, int status);
int uav_proto_decode_exit(const struct uav_proto_msg* msg, int* status);
int uav_proto_send_error(struct uav_transport* transport, int error);
int uav_proto_decode_error(const struct uav_proto_msg* msg, int* error);

#endif  // !UAV_PROTOCOL_H
