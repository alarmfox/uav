#include "protocol_utils.h"

#include <errno.h>
#include <limits.h>
#include <stdlib.h>

#include "transport.h"

#define UAV_PROTO_HEADER_SIZE 16
#define UAV_PROTO_RESPONSE_STATUS_SIZE 4

static int uav_proto_kind_is_valid(uint16_t kind) {
  return kind == UAV_PROTO_REQUEST || kind == UAV_PROTO_RESPONSE ||
         kind == UAV_PROTO_EVENT || kind == UAV_PROTO_STREAM;
}

int uav_proto_send_frame(struct uav_transport* transport, uint32_t magic,
                         uint16_t version, uint16_t kind, uint16_t type,
                         const void* payload, uint32_t length) {
  const struct uav_proto_header header = {
      .magic = magic,
      .version = version,
      .kind = kind,
      .type = type,
      .length = length,
  };
  uint8_t encoded_header[UAV_PROTO_HEADER_SIZE];

  if (transport == NULL || !uav_proto_kind_is_valid(kind) ||
      (payload == NULL && length > 0)) {
    errno = EINVAL;
    return -1;
  }

  if (length > UAV_PROTO_MAX_PAYLOAD) {
    errno = EMSGSIZE;
    return -1;
  }

  uav_proto_put_u32(encoded_header, header.magic);
  uav_proto_put_u16(encoded_header + 4, header.version);
  uav_proto_put_u16(encoded_header + 6, header.kind);
  uav_proto_put_u16(encoded_header + 8, header.type);
  uav_proto_put_u32(encoded_header + 12, header.length);

  if (uav_transport_write_all(transport, encoded_header,
                              sizeof(encoded_header)) < 0)
    return -1;

  if (length > 0 && uav_transport_write_all(transport, payload, length) < 0)
    return -1;

  return 0;
}

int uav_proto_recv_frame(struct uav_transport* transport, uint32_t magic,
                         uint16_t version, struct uav_proto_msg* msg) {
  struct uav_proto_header header;
  uint8_t encoded_header[UAV_PROTO_HEADER_SIZE];

  if (transport == NULL || msg == NULL) {
    errno = EINVAL;
    return -1;
  }

  if (uav_transport_read_all(transport, encoded_header,
                             sizeof(encoded_header)) < 0)
    return -1;

  header.magic = uav_proto_get_u32(encoded_header);
  header.version = uav_proto_get_u16(encoded_header + 4);
  header.kind = uav_proto_get_u16(encoded_header + 6);
  header.type = uav_proto_get_u16(encoded_header + 8);
  header.length = uav_proto_get_u32(encoded_header + 12);

  if (header.magic != magic || header.version != version ||
      !uav_proto_kind_is_valid(header.kind)) {
    errno = EPROTO;
    return -1;
  }

  if (header.length > sizeof(msg->payload)) {
    errno = EMSGSIZE;
    return -1;
  }

  msg->header = header;

  if (header.length > 0 &&
      uav_transport_read_all(transport, msg->payload, header.length) < 0)
    return -1;

  return 0;
}

int uav_proto_send_request(struct uav_transport* transport, uint32_t magic,
                           uint16_t version, uint16_t type,
                           const void* payload, uint32_t length) {
  return uav_proto_send_frame(transport, magic, version, UAV_PROTO_REQUEST,
                              type, payload, length);
}

int uav_proto_send_response(struct uav_transport* transport, uint32_t magic,
                            uint16_t version, uint16_t request_type,
                            int error, const void* body,
                            uint32_t body_length) {
  uint8_t* payload;
  int ret;

  if (error < 0 || body_length > UAV_PROTO_MAX_PAYLOAD -
                                 UAV_PROTO_RESPONSE_STATUS_SIZE ||
      (body == NULL && body_length > 0)) {
    errno = EINVAL;
    return -1;
  }

  payload = malloc(UAV_PROTO_RESPONSE_STATUS_SIZE + body_length);
  if (payload == NULL) {
    errno = ENOMEM;
    return -1;
  }
  uav_proto_put_u32(payload, (uint32_t)error);
  if (body_length > 0)
    memcpy(payload + UAV_PROTO_RESPONSE_STATUS_SIZE, body, body_length);

  ret = uav_proto_send_frame(transport, magic, version, UAV_PROTO_RESPONSE,
                             request_type, payload,
                             UAV_PROTO_RESPONSE_STATUS_SIZE + body_length);
  free(payload);
  return ret;
}

int uav_proto_send_event(struct uav_transport* transport, uint32_t magic,
                         uint16_t version, uint16_t type,
                         const void* payload, uint32_t length) {
  return uav_proto_send_frame(transport, magic, version, UAV_PROTO_EVENT,
                              type, payload, length);
}

int uav_proto_send_stream(struct uav_transport* transport, uint32_t magic,
                          uint16_t version, uint16_t type,
                          const void* payload, uint32_t length) {
  return uav_proto_send_frame(transport, magic, version, UAV_PROTO_STREAM,
                              type, payload, length);
}

int uav_proto_decode_response(const struct uav_proto_msg* msg,
                              uint16_t expected_type, int* error,
                              const uint8_t** body, uint32_t* body_length) {
  uint32_t status;

  if (msg == NULL || error == NULL || body == NULL || body_length == NULL) {
    errno = EINVAL;
    return -1;
  }
  if (msg->header.kind != UAV_PROTO_RESPONSE ||
      msg->header.type != expected_type ||
      msg->header.length < UAV_PROTO_RESPONSE_STATUS_SIZE) {
    errno = EPROTO;
    return -1;
  }

  status = uav_proto_get_u32(msg->payload);
  if (status > INT_MAX) {
    errno = EPROTO;
    return -1;
  }

  *error = (int)status;
  *body = msg->payload + UAV_PROTO_RESPONSE_STATUS_SIZE;
  *body_length = msg->header.length - UAV_PROTO_RESPONSE_STATUS_SIZE;
  return 0;
}
