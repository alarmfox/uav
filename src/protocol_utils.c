#include "protocol_utils.h"

#include <errno.h>

#include "transport.h"

#define UAV_PROTO_HEADER_SIZE 12

int uav_proto_send_frame(struct uav_transport* transport, uint32_t magic,
                         uint16_t version, uint16_t type, const void* payload,
                         uint32_t length) {
  const struct uav_proto_header header = {
      .magic = magic,
      .version = version,
      .type = type,
      .length = length,
  };
  uint8_t encoded_header[UAV_PROTO_HEADER_SIZE];

  if (transport == NULL || (payload == NULL && length > 0)) {
    errno = EINVAL;
    return -1;
  }

  if (length > UAV_PROTO_MAX_PAYLOAD) {
    errno = EMSGSIZE;
    return -1;
  }

  uav_proto_put_u32(encoded_header, header.magic);
  uav_proto_put_u16(encoded_header + 4, header.version);
  uav_proto_put_u16(encoded_header + 6, header.type);
  uav_proto_put_u32(encoded_header + 8, header.length);

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
  header.type = uav_proto_get_u16(encoded_header + 6);
  header.length = uav_proto_get_u32(encoded_header + 8);

  if (header.magic != magic || header.version != version) {
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
