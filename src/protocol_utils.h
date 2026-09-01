#ifndef UAV_PROTOCOL_UTILS_H
#define UAV_PROTOCOL_UTILS_H

#include <arpa/inet.h>
#include <stdint.h>
#include <string.h>

#define UAV_PROTO_MAX_PAYLOAD (64 * 1024)

/* Decoded header fields in host byte order. */
struct uav_proto_header {
  uint32_t magic;
  uint16_t version;
  uint16_t type;
  uint32_t length;
};

struct uav_proto_msg {
  struct uav_proto_header header;
  uint8_t payload[UAV_PROTO_MAX_PAYLOAD];
};

struct uav_transport;

static inline void uav_proto_put_u16(uint8_t* destination, uint16_t value) {
  value = htons(value);
  memcpy(destination, &value, sizeof(value));
}

static inline void uav_proto_put_u32(uint8_t* destination, uint32_t value) {
  value = htonl(value);
  memcpy(destination, &value, sizeof(value));
}

static inline uint16_t uav_proto_get_u16(const uint8_t* source) {
  uint16_t value;

  memcpy(&value, source, sizeof(value));
  return ntohs(value);
}

static inline uint32_t uav_proto_get_u32(const uint8_t* source) {
  uint32_t value;

  memcpy(&value, source, sizeof(value));
  return ntohl(value);
}

int uav_proto_send_frame(struct uav_transport* transport, uint32_t magic,
                         uint16_t version, uint16_t type, const void* payload,
                         uint32_t length);
int uav_proto_recv_frame(struct uav_transport* transport, uint32_t magic,
                         uint16_t version, struct uav_proto_msg* msg);

#endif  // !UAV_PROTOCOL_UTILS_H
