#include "agent_protocol.h"

#include <errno.h>
#include <limits.h>
#include <unistd.h>

#include "protocol_utils.h"
#include "transport.h"
#include "utils.h"

#define UAV_UPLOAD_META_SIZE 12
#define UAV_STATUS_SIZE 4

static int uav_agent_proto_expect_empty(struct uav_transport* transport,
                                        uint16_t type) {
  struct uav_proto_msg msg;
  int remote_error;

  if (uav_agent_proto_recv(transport, &msg) < 0) return -1;

  if (msg.header.type == UAV_AGENT_MSG_ERROR) {
    if (uav_agent_proto_decode_error(&msg, &remote_error) < 0) return -1;
    errno = remote_error;
    return -1;
  }

  if (msg.header.type != type || msg.header.length != 0) {
    errno = EPROTO;
    return -1;
  }

  return 0;
}

static int uav_agent_proto_send_u32(struct uav_transport* transport,
                                    uint16_t type, uint32_t value) {
  uint8_t payload[UAV_STATUS_SIZE];

  uav_proto_put_u32(payload, value);
  return uav_agent_proto_send(transport, type, payload, sizeof(payload));
}

static int uav_agent_proto_decode_u32(const struct uav_proto_msg* msg,
                                      uint16_t type, uint32_t* value) {
  if (msg == NULL || value == NULL) {
    errno = EINVAL;
    return -1;
  }

  if (msg->header.type != type || msg->header.length != UAV_STATUS_SIZE) {
    errno = EPROTO;
    return -1;
  }

  *value = uav_proto_get_u32(msg->payload);
  return 0;
}

int uav_agent_proto_send(struct uav_transport* transport, uint16_t type,
                         const void* payload, uint32_t length) {
  return uav_proto_send_frame(transport, UAV_AGENT_PROTO_MAGIC,
                              UAV_AGENT_PROTO_VERSION, type, payload, length);
}

int uav_agent_proto_recv(struct uav_transport* transport,
                         struct uav_proto_msg* msg) {
  return uav_proto_recv_frame(transport, UAV_AGENT_PROTO_MAGIC,
                              UAV_AGENT_PROTO_VERSION, msg);
}

int uav_agent_proto_upload(struct uav_transport* transport, int source_fd,
                           const struct uav_agent_upload_meta* meta) {
  uint8_t begin[UAV_UPLOAD_META_SIZE];
  uint8_t chunk[UAV_AGENT_PROTO_MAX_CHUNK];
  uint32_t remaining;

  if (transport == NULL || source_fd < 0 || meta == NULL || meta->size == 0 ||
      (meta->source_mode & ~0777U) != 0 ||
      (meta->purpose != UAV_AGENT_UPLOAD_DATA &&
       meta->purpose != UAV_AGENT_UPLOAD_EXECUTABLE)) {
    errno = EINVAL;
    return -1;
  }

  uav_proto_put_u32(begin, meta->size);
  uav_proto_put_u32(begin + 4, meta->source_mode);
  uav_proto_put_u32(begin + 8, (uint32_t)meta->purpose);

  if (uav_agent_proto_send(transport, UAV_AGENT_MSG_UPLOAD_BEGIN, begin,
                           sizeof(begin)) < 0)
    return -1;
  if (uav_agent_proto_expect_empty(transport, UAV_AGENT_MSG_UPLOAD_ACCEPT) < 0)
    return -1;

  remaining = meta->size;
  while (remaining > 0) {
    size_t wanted = remaining;
    ssize_t count;

    if (wanted > sizeof(chunk)) wanted = sizeof(chunk);

    do {
      count = read(source_fd, chunk, wanted);
    } while (count < 0 && errno == EINTR);

    if (count < 0) return -1;
    if (count == 0) {
      errno = EIO;
      return -1;
    }

    if (uav_agent_proto_send(transport, UAV_AGENT_MSG_UPLOAD_CHUNK, chunk,
                             (uint32_t)count) < 0)
      return -1;

    remaining -= (uint32_t)count;
  }

  if (uav_agent_proto_send(transport, UAV_AGENT_MSG_UPLOAD_END, NULL, 0) < 0)
    return -1;
  return uav_agent_proto_expect_empty(transport, UAV_AGENT_MSG_UPLOAD_DONE);
}

int uav_agent_proto_decode_upload_begin(const struct uav_proto_msg* msg,
                                        struct uav_agent_upload_meta* meta) {
  uint32_t purpose;

  if (msg == NULL || meta == NULL) {
    errno = EINVAL;
    return -1;
  }

  if (msg->header.type != UAV_AGENT_MSG_UPLOAD_BEGIN ||
      msg->header.length != UAV_UPLOAD_META_SIZE) {
    errno = EPROTO;
    return -1;
  }

  meta->size = uav_proto_get_u32(msg->payload);
  meta->source_mode = uav_proto_get_u32(msg->payload + 4);
  purpose = uav_proto_get_u32(msg->payload + 8);

  if (meta->size == 0 || (meta->source_mode & ~0777U) != 0 ||
      (purpose != UAV_AGENT_UPLOAD_DATA &&
       purpose != UAV_AGENT_UPLOAD_EXECUTABLE)) {
    errno = EPROTO;
    return -1;
  }

  meta->purpose = (enum uav_agent_upload_purpose)purpose;
  return 0;
}

int uav_agent_proto_accept_upload(struct uav_transport* transport) {
  return uav_agent_proto_send(transport, UAV_AGENT_MSG_UPLOAD_ACCEPT, NULL, 0);
}

int uav_agent_proto_receive_upload(struct uav_transport* transport,
                                   int destination_fd, uint32_t size) {
  struct uav_proto_msg msg;
  uint32_t remaining;

  if (transport == NULL || destination_fd < 0 || size == 0) {
    errno = EINVAL;
    return -1;
  }

  remaining = size;
  while (remaining > 0) {
    if (uav_agent_proto_recv(transport, &msg) < 0) return -1;

    if (msg.header.type != UAV_AGENT_MSG_UPLOAD_CHUNK ||
        msg.header.length == 0 ||
        msg.header.length > UAV_AGENT_PROTO_MAX_CHUNK ||
        msg.header.length > remaining) {
      errno = EPROTO;
      return -1;
    }

    if (uav_write_all(destination_fd, msg.payload, msg.header.length) < 0)
      return -1;

    remaining -= msg.header.length;
  }

  if (uav_agent_proto_recv(transport, &msg) < 0) return -1;
  if (msg.header.type != UAV_AGENT_MSG_UPLOAD_END || msg.header.length != 0) {
    errno = EPROTO;
    return -1;
  }

  return 0;
}

int uav_agent_proto_complete_upload(struct uav_transport* transport) {
  return uav_agent_proto_send(transport, UAV_AGENT_MSG_UPLOAD_DONE, NULL, 0);
}

int uav_agent_proto_send_exit(struct uav_transport* transport, int status) {
  if (status < 0) {
    errno = EINVAL;
    return -1;
  }

  return uav_agent_proto_send_u32(transport, UAV_AGENT_MSG_EXIT,
                                  (uint32_t)status);
}

int uav_agent_proto_decode_exit(const struct uav_proto_msg* msg, int* status) {
  uint32_t value;

  if (status == NULL) {
    errno = EINVAL;
    return -1;
  }
  if (uav_agent_proto_decode_u32(msg, UAV_AGENT_MSG_EXIT, &value) < 0)
    return -1;
  if (value > INT_MAX) {
    errno = EPROTO;
    return -1;
  }

  *status = (int)value;
  return 0;
}

int uav_agent_proto_send_error(struct uav_transport* transport, int error) {
  if (error <= 0) {
    errno = EINVAL;
    return -1;
  }

  return uav_agent_proto_send_u32(transport, UAV_AGENT_MSG_ERROR,
                                  (uint32_t)error);
}

int uav_agent_proto_decode_error(const struct uav_proto_msg* msg, int* error) {
  uint32_t value;

  if (error == NULL) {
    errno = EINVAL;
    return -1;
  }
  if (uav_agent_proto_decode_u32(msg, UAV_AGENT_MSG_ERROR, &value) < 0)
    return -1;
  if (value == 0 || value > INT_MAX) {
    errno = EPROTO;
    return -1;
  }

  *error = (int)value;
  return 0;
}
