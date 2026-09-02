#ifndef UAV_PROTOCOL_UTILS_H
#define UAV_PROTOCOL_UTILS_H

#include <arpa/inet.h>
#include <stdint.h>
#include <string.h>

#define UAV_PROTO_MAX_PAYLOAD (64 * 1024)

enum uav_proto_message_kind {
  UAV_PROTO_REQUEST = 1,
  UAV_PROTO_RESPONSE,
  UAV_PROTO_EVENT,
  UAV_PROTO_STREAM,
};

/* Decoded header fields in host byte order. */
struct uav_proto_header {
  uint32_t magic;
  uint16_t version;
  uint16_t kind;
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
                         uint16_t version, uint16_t kind, uint16_t type,
                         const void* payload, uint32_t length);
int uav_proto_recv_frame(struct uav_transport* transport, uint32_t magic,
                         uint16_t version, struct uav_proto_msg* msg);

int uav_proto_send_request(struct uav_transport* transport, uint32_t magic,
                           uint16_t version, uint16_t type,
                           const void* payload, uint32_t length);
int uav_proto_send_response(struct uav_transport* transport, uint32_t magic,
                            uint16_t version, uint16_t request_type,
                            int error, const void* body,
                            uint32_t body_length);
int uav_proto_send_event(struct uav_transport* transport, uint32_t magic,
                         uint16_t version, uint16_t type,
                         const void* payload, uint32_t length);
int uav_proto_send_stream(struct uav_transport* transport, uint32_t magic,
                          uint16_t version, uint16_t type,
                          const void* payload, uint32_t length);
int uav_proto_decode_response(const struct uav_proto_msg* msg,
                              uint16_t expected_type, int* error,
                              const uint8_t** body, uint32_t* body_length);

#endif  // !UAV_PROTOCOL_UTILS_H
