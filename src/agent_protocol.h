#ifndef UAV_AGENT_PROTOCOL_H
#define UAV_AGENT_PROTOCOL_H

#include <stddef.h>
#include <stdint.h>

#include "protocol_utils.h"

#define UAV_AGENT_PROTO_MAGIC 0x55415653u /* "UAVS" */
#define UAV_AGENT_PROTO_VERSION 3
#define UAV_AGENT_PROTO_MAX_CHUNK (8 * 1024)
#define UAV_AGENT_PROTO_MAX_EXEC_ENTRIES 4096U

#define UAV_AGENT_EXEC_FLAG_ALLOW_LOADER_ENV (1U << 0)
#define UAV_AGENT_EXEC_FLAG_MASK UAV_AGENT_EXEC_FLAG_ALLOW_LOADER_ENV

enum uav_agent_proto_msg_type {
  UAV_AGENT_MSG_START = 1,
  UAV_AGENT_MSG_UPLOAD_BEGIN,
  UAV_AGENT_MSG_UPLOAD_CHUNK,
  UAV_AGENT_MSG_UPLOAD_END,
  UAV_AGENT_MSG_RUN,
  UAV_AGENT_MSG_KILL,
  UAV_AGENT_MSG_SHUTDOWN,
  UAV_AGENT_MSG_PROGRAM_EXIT,
  UAV_AGENT_MSG_EVENT,
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

/* Caller-owned, host-order execution parameters. */
struct uav_agent_exec_params {
  uint32_t flags;
  size_t argc;
  const char* const* argv;
  size_t envc;
  const char* const* envp;
};

/* Owned, decoded execution request. */
struct uav_agent_exec_request {
  uint32_t duration_seconds;
  uint32_t flags;
  uint32_t argc;
  uint32_t envc;
  char** argv;
  char** envp;
  void* storage;
};

struct uav_transport;

int uav_agent_proto_send_request(struct uav_transport* transport,
                                 uint16_t type, const void* data,
                                 uint32_t length);
int uav_agent_proto_send_response(struct uav_transport* transport,
                                  uint16_t request_type, int error,
                                  const void* body, uint32_t body_length);
int uav_agent_proto_send_event(struct uav_transport* transport, uint16_t type,
                               const void* data, uint32_t length);
int uav_agent_proto_send_stream(struct uav_transport* transport,
                                uint16_t type, const void* data,
                                uint32_t length);
int uav_agent_proto_recv(struct uav_transport* transport,
                         struct uav_proto_msg* msg);
int uav_agent_proto_decode_response(const struct uav_proto_msg* msg,
                                    uint16_t request_type, int* error,
                                    const uint8_t** body,
                                    uint32_t* body_length);

int uav_agent_proto_send_run(struct uav_transport* transport,
                             const struct uav_agent_exec_params* params,
                             uint32_t duration_seconds);
int uav_agent_proto_decode_run(const struct uav_proto_msg* msg,
                               struct uav_agent_exec_request* request);
void uav_agent_proto_free_run(struct uav_agent_exec_request* request);

int uav_agent_proto_upload(struct uav_transport* transport, int source_fd,
                           const struct uav_agent_upload_meta* meta);
int uav_agent_proto_decode_upload_begin(const struct uav_proto_msg* msg,
                                        struct uav_agent_upload_meta* meta);
int uav_agent_proto_receive_upload(struct uav_transport* transport,
                                   int destination_fd, uint32_t size);

int uav_agent_proto_send_program_exit(struct uav_transport* transport,
                                      int status);
int uav_agent_proto_decode_program_exit(const struct uav_proto_msg* msg,
                                        int* status);

#endif  // !UAV_AGENT_PROTOCOL_H
