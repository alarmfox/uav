#ifndef UAV_AGENT_PROTOCOL_H
#define UAV_AGENT_PROTOCOL_H

#include <stdint.h>

#include "protocol_utils.h"

#define UAV_AGENT_PROTO_MAGIC 0x55415653u /* "UAVS" */
#define UAV_AGENT_PROTO_VERSION 1
#define UAV_AGENT_PROTO_MAX_CHUNK (8 * 1024)

enum uav_agent_proto_msg_type {
  UAV_AGENT_MSG_HELLO = 1,
  UAV_AGENT_MSG_READY,
  UAV_AGENT_MSG_STR,

  UAV_AGENT_MSG_UPLOAD_BEGIN,
  UAV_AGENT_MSG_UPLOAD_ACCEPT,
  UAV_AGENT_MSG_UPLOAD_CHUNK,
  UAV_AGENT_MSG_UPLOAD_END,
  UAV_AGENT_MSG_UPLOAD_DONE,

  UAV_AGENT_MSG_RUN,
  UAV_AGENT_MSG_KILL,
  UAV_AGENT_MSG_EXIT,
  UAV_AGENT_MSG_EVENT,
  UAV_AGENT_MSG_ERROR
};

enum uav_agent_upload_purpose {
  UAV_AGENT_UPLOAD_DATA = 1,
  UAV_AGENT_UPLOAD_EXECUTABLE,
};

/* Host-order values. agent_protocol.c owns their wire representation. */
struct uav_agent_upload_meta {
  uint32_t size;
  uint32_t source_mode;
  enum uav_agent_upload_purpose purpose;
};

struct uav_transport;

int uav_agent_proto_send(struct uav_transport* transport, uint16_t type,
                         const void* data, uint32_t length);
int uav_agent_proto_recv(struct uav_transport* transport,
                         struct uav_proto_msg* msg);

int uav_agent_proto_upload(struct uav_transport* transport, int source_fd,
                           const struct uav_agent_upload_meta* meta);
int uav_agent_proto_decode_upload_begin(const struct uav_proto_msg* msg,
                                        struct uav_agent_upload_meta* meta);
int uav_agent_proto_accept_upload(struct uav_transport* transport);
int uav_agent_proto_receive_upload(struct uav_transport* transport,
                                   int destination_fd, uint32_t size);
int uav_agent_proto_complete_upload(struct uav_transport* transport);

int uav_agent_proto_send_exit(struct uav_transport* transport, int status);
int uav_agent_proto_decode_exit(const struct uav_proto_msg* msg, int* status);
int uav_agent_proto_send_error(struct uav_transport* transport, int error);
int uav_agent_proto_decode_error(const struct uav_proto_msg* msg, int* error);

#endif  // !UAV_AGENT_PROTOCOL_H
