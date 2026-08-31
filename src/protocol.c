#include "protocol.h"

#include <arpa/inet.h>
#include <errno.h>
#include <limits.h>
#include <string.h>
#include <unistd.h>

#include "transport.h"
#include "utils.h"

#define UAV_PROTO_HEADER_SIZE 12
#define UAV_UPLOAD_META_SIZE 12
#define UAV_STATUS_SIZE 4

static void uav_proto_put_u16(uint8_t* destination, uint16_t value) {
  value = htons(value);
  memcpy(destination, &value, sizeof(value));
}

static void uav_proto_put_u32(uint8_t* destination, uint32_t value) {
  value = htonl(value);
  memcpy(destination, &value, sizeof(value));
}

static uint16_t uav_proto_get_u16(const uint8_t* source) {
  uint16_t value;

  memcpy(&value, source, sizeof(value));
  return ntohs(value);
}

static uint32_t uav_proto_get_u32(const uint8_t* source) {
  uint32_t value;

  memcpy(&value, source, sizeof(value));
  return ntohl(value);
}

static int uav_proto_expect_empty(struct uav_transport* transport,
                                  uint16_t type) {
  struct uav_proto_msg msg;
  int remote_error;

  if (uav_proto_recv(transport, &msg) < 0) return -1;

  if (msg.type == UAV_MSG_ERROR) {
    if (uav_proto_decode_error(&msg, &remote_error) < 0) return -1;
    errno = remote_error;
    return -1;
  }

  if (msg.type != type || msg.length != 0) {
    errno = EPROTO;
    return -1;
  }

  return 0;
}

static int uav_proto_send_u32(struct uav_transport* transport, uint16_t type,
                              uint32_t value) {
  uint8_t payload[UAV_STATUS_SIZE];

  uav_proto_put_u32(payload, value);
  return uav_proto_send(transport, type, payload, sizeof(payload));
}

static int uav_proto_decode_u32(const struct uav_proto_msg* msg, uint16_t type,
                                uint32_t* value) {
  if (msg == NULL || value == NULL) {
    errno = EINVAL;
    return -1;
  }

  if (msg->type != type || msg->length != UAV_STATUS_SIZE) {
    errno = EPROTO;
    return -1;
  }

  *value = uav_proto_get_u32(msg->payload);
  return 0;
}

int uav_proto_send(struct uav_transport* transport, uint16_t type,
                   const void* payload, uint32_t length) {
  uint8_t header[UAV_PROTO_HEADER_SIZE];

  if (transport == NULL || (payload == NULL && length > 0)) {
    errno = EINVAL;
    return -1;
  }

  if (length > UAV_PROTO_MAX_PAYLOAD) {
    errno = EMSGSIZE;
    return -1;
  }

  uav_proto_put_u32(header, UAV_PROTO_MAGIC);
  uav_proto_put_u16(header + 4, UAV_PROTO_VERSION);
  uav_proto_put_u16(header + 6, type);
  uav_proto_put_u32(header + 8, length);

  if (uav_transport_write_all(transport, header, sizeof(header)) < 0) return -1;

  if (length > 0 && uav_transport_write_all(transport, payload, length) < 0)
    return -1;

  return 0;
}

int uav_proto_recv(struct uav_transport* transport, struct uav_proto_msg* msg) {
  uint8_t header[UAV_PROTO_HEADER_SIZE];
  uint32_t length;

  if (transport == NULL || msg == NULL) {
    errno = EINVAL;
    return -1;
  }

  if (uav_transport_read_all(transport, header, sizeof(header)) < 0) return -1;

  if (uav_proto_get_u32(header) != UAV_PROTO_MAGIC ||
      uav_proto_get_u16(header + 4) != UAV_PROTO_VERSION) {
    errno = EPROTO;
    return -1;
  }

  length = uav_proto_get_u32(header + 8);
  if (length > sizeof(msg->payload)) {
    errno = EMSGSIZE;
    return -1;
  }

  msg->type = uav_proto_get_u16(header + 6);
  msg->length = length;

  if (length > 0 && uav_transport_read_all(transport, msg->payload, length) < 0)
    return -1;

  return 0;
}

int uav_proto_upload(struct uav_transport* transport, int source_fd,
                     const struct uav_upload_meta* meta) {
  uint8_t begin[UAV_UPLOAD_META_SIZE];
  uint8_t chunk[UAV_PROTO_MAX_CHUNK];
  uint32_t remaining;

  if (transport == NULL || source_fd < 0 || meta == NULL || meta->size == 0 ||
      (meta->source_mode & ~0777U) != 0 ||
      (meta->purpose != UAV_UPLOAD_DATA &&
       meta->purpose != UAV_UPLOAD_EXECUTABLE)) {
    errno = EINVAL;
    return -1;
  }

  uav_proto_put_u32(begin, meta->size);
  uav_proto_put_u32(begin + 4, meta->source_mode);
  uav_proto_put_u32(begin + 8, (uint32_t)meta->purpose);

  if (uav_proto_send(transport, UAV_MSG_UPLOAD_BEGIN, begin, sizeof(begin)) < 0)
    return -1;
  if (uav_proto_expect_empty(transport, UAV_MSG_UPLOAD_ACCEPT) < 0) return -1;

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

    if (uav_proto_send(transport, UAV_MSG_UPLOAD_CHUNK, chunk,
                       (uint32_t)count) < 0)
      return -1;

    remaining -= (uint32_t)count;
  }

  if (uav_proto_send(transport, UAV_MSG_UPLOAD_END, NULL, 0) < 0) return -1;
  return uav_proto_expect_empty(transport, UAV_MSG_UPLOAD_DONE);
}

int uav_proto_decode_upload_begin(const struct uav_proto_msg* msg,
                                  struct uav_upload_meta* meta) {
  uint32_t purpose;

  if (msg == NULL || meta == NULL) {
    errno = EINVAL;
    return -1;
  }

  if (msg->type != UAV_MSG_UPLOAD_BEGIN ||
      msg->length != UAV_UPLOAD_META_SIZE) {
    errno = EPROTO;
    return -1;
  }

  meta->size = uav_proto_get_u32(msg->payload);
  meta->source_mode = uav_proto_get_u32(msg->payload + 4);
  purpose = uav_proto_get_u32(msg->payload + 8);

  if (meta->size == 0 || (meta->source_mode & ~0777U) != 0 ||
      (purpose != UAV_UPLOAD_DATA && purpose != UAV_UPLOAD_EXECUTABLE)) {
    errno = EPROTO;
    return -1;
  }

  meta->purpose = (enum uav_upload_purpose)purpose;
  return 0;
}

int uav_proto_accept_upload(struct uav_transport* transport) {
  return uav_proto_send(transport, UAV_MSG_UPLOAD_ACCEPT, NULL, 0);
}

int uav_proto_receive_upload(struct uav_transport* transport,
                             int destination_fd, uint32_t size) {
  struct uav_proto_msg msg;
  uint32_t remaining;

  if (transport == NULL || destination_fd < 0 || size == 0) {
    errno = EINVAL;
    return -1;
  }

  remaining = size;
  while (remaining > 0) {
    if (uav_proto_recv(transport, &msg) < 0) return -1;

    if (msg.type != UAV_MSG_UPLOAD_CHUNK || msg.length == 0 ||
        msg.length > UAV_PROTO_MAX_CHUNK || msg.length > remaining) {
      errno = EPROTO;
      return -1;
    }

    if (uav_fd_write_all(destination_fd, msg.payload, msg.length) < 0)
      return -1;

    remaining -= msg.length;
  }

  if (uav_proto_recv(transport, &msg) < 0) return -1;
  if (msg.type != UAV_MSG_UPLOAD_END || msg.length != 0) {
    errno = EPROTO;
    return -1;
  }

  return 0;
}

int uav_proto_complete_upload(struct uav_transport* transport) {
  return uav_proto_send(transport, UAV_MSG_UPLOAD_DONE, NULL, 0);
}

int uav_proto_send_exit(struct uav_transport* transport, int status) {
  if (status < 0) {
    errno = EINVAL;
    return -1;
  }

  return uav_proto_send_u32(transport, UAV_MSG_EXIT, (uint32_t)status);
}

int uav_proto_decode_exit(const struct uav_proto_msg* msg, int* status) {
  uint32_t value;

  if (status == NULL) {
    errno = EINVAL;
    return -1;
  }
  if (uav_proto_decode_u32(msg, UAV_MSG_EXIT, &value) < 0) return -1;
  if (value > INT_MAX) {
    errno = EPROTO;
    return -1;
  }

  *status = (int)value;
  return 0;
}

int uav_proto_send_error(struct uav_transport* transport, int error) {
  if (error <= 0) {
    errno = EINVAL;
    return -1;
  }

  return uav_proto_send_u32(transport, UAV_MSG_ERROR, (uint32_t)error);
}

int uav_proto_decode_error(const struct uav_proto_msg* msg, int* error) {
  uint32_t value;

  if (error == NULL) {
    errno = EINVAL;
    return -1;
  }
  if (uav_proto_decode_u32(msg, UAV_MSG_ERROR, &value) < 0) return -1;
  if (value == 0 || value > INT_MAX) {
    errno = EPROTO;
    return -1;
  }

  *error = (int)value;
  return 0;
}
