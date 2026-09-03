#ifndef UAV_PROTOCOL_UTILS_H
#define UAV_PROTOCOL_UTILS_H

#include <arpa/inet.h>
#include <stdint.h>
#include <string.h>

#define UAV_PROTO_MAX_PAYLOAD (64 * 1024)

enum uav_proto_message_kind {
  UAV_PROTO_REQUEST = 1,
  UAV_PROTO_RESPONSE,
};

/* Decoded message. Wire framing is deliberately not exposed to callers. */
struct uav_proto_msg {
  uint16_t type;
  int error;
  uint32_t length;
  uint8_t payload[UAV_PROTO_MAX_PAYLOAD];
};

struct ucred;

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

int uav_proto_stream_send(int fd, uint32_t magic, uint16_t version,
                          uint16_t kind, uint16_t type, int error,
                          const void* payload, uint32_t length);
int uav_proto_stream_receive(int fd, uint32_t magic, uint16_t version,
                             uint16_t expected_kind,
                             struct uav_proto_msg* msg);

int uav_proto_seqpacket_send(int fd, uint32_t magic, uint16_t version,
                             uint16_t kind, uint16_t type, int error,
                             const void* payload, uint32_t length);
int uav_proto_seqpacket_receive(int fd, uint32_t magic, uint16_t version,
                                uint16_t expected_kind,
                                struct uav_proto_msg* msg,
                                struct ucred* credentials);

#endif  // !UAV_PROTOCOL_UTILS_H
