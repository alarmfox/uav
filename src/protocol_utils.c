#include "protocol_utils.h"

#include <errno.h>
#include <limits.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <unistd.h>

#define UAV_PROTO_HEADER_SIZE 16U
#define UAV_PROTO_RESPONSE_STATUS_SIZE 4U

static int uav_proto_validate_send(int fd, uint16_t kind, int error,
                                   const void* payload, uint32_t length,
                                   uint32_t* wire_length) {
  if (fd < 0 || wire_length == NULL ||
      (kind != UAV_PROTO_REQUEST && kind != UAV_PROTO_RESPONSE) ||
      (payload == NULL && length > 0) || error < 0 ||
      (kind == UAV_PROTO_REQUEST && error != 0)) {
    errno = EINVAL;
    return -1;
  }

  if (length > UAV_PROTO_MAX_PAYLOAD ||
      (kind == UAV_PROTO_RESPONSE &&
       length > UAV_PROTO_MAX_PAYLOAD - UAV_PROTO_RESPONSE_STATUS_SIZE)) {
    errno = EMSGSIZE;
    return -1;
  }

  *wire_length = length;
  if (kind == UAV_PROTO_RESPONSE)
    *wire_length += UAV_PROTO_RESPONSE_STATUS_SIZE;
  return 0;
}

static void uav_proto_encode_header(uint8_t header[UAV_PROTO_HEADER_SIZE],
                                    uint32_t magic, uint16_t version,
                                    uint16_t kind, uint16_t type,
                                    uint32_t length) {
  memset(header, 0, UAV_PROTO_HEADER_SIZE);
  uav_proto_put_u32(header, magic);
  uav_proto_put_u16(header + 4, version);
  uav_proto_put_u16(header + 6, kind);
  uav_proto_put_u16(header + 8, type);
  uav_proto_put_u16(header + 10, 0);
  uav_proto_put_u32(header + 12, length);
}

static int uav_proto_decode_header(
    const uint8_t header[UAV_PROTO_HEADER_SIZE], uint32_t magic,
    uint16_t version, uint16_t expected_kind, uint16_t* type,
    uint32_t* length) {
  uint16_t kind;

  if (type == NULL || length == NULL ||
      (expected_kind != UAV_PROTO_REQUEST &&
       expected_kind != UAV_PROTO_RESPONSE)) {
    errno = EINVAL;
    return -1;
  }

  kind = uav_proto_get_u16(header + 6);
  if (uav_proto_get_u32(header) != magic ||
      uav_proto_get_u16(header + 4) != version || kind != expected_kind ||
      uav_proto_get_u16(header + 10) != 0) {
    errno = EPROTO;
    return -1;
  }

  *type = uav_proto_get_u16(header + 8);
  *length = uav_proto_get_u32(header + 12);
  if (*length > UAV_PROTO_MAX_PAYLOAD ||
      (kind == UAV_PROTO_RESPONSE &&
       *length < UAV_PROTO_RESPONSE_STATUS_SIZE)) {
    errno = *length > UAV_PROTO_MAX_PAYLOAD ? EMSGSIZE : EPROTO;
    return -1;
  }

  return 0;
}

static int uav_proto_finish_receive(struct uav_proto_msg* msg,
                                    uint16_t expected_kind,
                                    uint32_t wire_length) {
  uint32_t status;

  msg->error = 0;
  msg->length = wire_length;
  if (expected_kind == UAV_PROTO_REQUEST) return 0;

  status = uav_proto_get_u32(msg->payload);
  if (status > INT_MAX) {
    errno = EPROTO;
    return -1;
  }

  msg->error = (int)status;
  msg->length -= UAV_PROTO_RESPONSE_STATUS_SIZE;
  if (msg->length > 0)
    memmove(msg->payload, msg->payload + UAV_PROTO_RESPONSE_STATUS_SIZE,
            msg->length);
  return 0;
}

static int uav_read_full(int fd, void* buffer, size_t size) {
  uint8_t* position = buffer;

  while (size > 0) {
    ssize_t received = read(fd, position, size);

    if (received < 0) {
      if (errno == EINTR) continue;
      return -1;
    }
    if (received == 0) {
      errno = ECONNRESET;
      return -1;
    }

    position += (size_t)received;
    size -= (size_t)received;
  }
  return 0;
}

static int uav_write_full(int fd, const void* buffer, size_t size) {
  const uint8_t* position = buffer;

  while (size > 0) {
    ssize_t written = send(fd, position, size, MSG_NOSIGNAL);

    if (written < 0 && errno == ENOTSOCK)
      written = write(fd, position, size);
    if (written < 0) {
      if (errno == EINTR) continue;
      return -1;
    }
    if (written == 0) {
      errno = EIO;
      return -1;
    }

    position += (size_t)written;
    size -= (size_t)written;
  }
  return 0;
}

int uav_proto_stream_send(int fd, uint32_t magic, uint16_t version,
                          uint16_t kind, uint16_t type, int error,
                          const void* payload, uint32_t length) {
  uint8_t header[UAV_PROTO_HEADER_SIZE];
  uint8_t status[UAV_PROTO_RESPONSE_STATUS_SIZE];
  uint32_t wire_length;

  if (uav_proto_validate_send(fd, kind, error, payload, length,
                              &wire_length) < 0)
    return -1;

  uav_proto_encode_header(header, magic, version, kind, type, wire_length);
  if (uav_write_full(fd, header, sizeof(header)) < 0) return -1;

  if (kind == UAV_PROTO_RESPONSE) {
    uav_proto_put_u32(status, (uint32_t)error);
    if (uav_write_full(fd, status, sizeof(status)) < 0) return -1;
  }
  if (length > 0 && uav_write_full(fd, payload, length) < 0) return -1;
  return 0;
}

int uav_proto_stream_receive(int fd, uint32_t magic, uint16_t version,
                             uint16_t expected_kind,
                             struct uav_proto_msg* msg) {
  uint8_t header[UAV_PROTO_HEADER_SIZE];
  uint32_t wire_length;

  if (fd < 0 || msg == NULL) {
    errno = EINVAL;
    return -1;
  }

  if (uav_read_full(fd, header, sizeof(header)) < 0) return -1;
  if (uav_proto_decode_header(header, magic, version, expected_kind, &msg->type,
                              &wire_length) < 0)
    return -1;
  if (wire_length > 0 && uav_read_full(fd, msg->payload, wire_length) < 0)
    return -1;

  return uav_proto_finish_receive(msg, expected_kind, wire_length);
}

int uav_proto_seqpacket_send(int fd, uint32_t magic, uint16_t version,
                             uint16_t kind, uint16_t type, int error,
                             const void* payload, uint32_t length) {
  uint8_t header[UAV_PROTO_HEADER_SIZE];
  uint8_t status[UAV_PROTO_RESPONSE_STATUS_SIZE];
  struct iovec iov[3];
  struct msghdr message;
  uint32_t wire_length;
  size_t iov_count = 1;
  ssize_t sent;

  if (uav_proto_validate_send(fd, kind, error, payload, length,
                              &wire_length) < 0)
    return -1;

  uav_proto_encode_header(header, magic, version, kind, type, wire_length);
  iov[0] = (struct iovec){.iov_base = header, .iov_len = sizeof(header)};
  if (kind == UAV_PROTO_RESPONSE) {
    uav_proto_put_u32(status, (uint32_t)error);
    iov[iov_count++] =
        (struct iovec){.iov_base = status, .iov_len = sizeof(status)};
  }
  if (length > 0)
    iov[iov_count++] =
        (struct iovec){.iov_base = (void*)payload, .iov_len = length};

  memset(&message, 0, sizeof(message));
  message.msg_iov = iov;
  message.msg_iovlen = iov_count;

  do {
    sent = sendmsg(fd, &message, MSG_NOSIGNAL);
  } while (sent < 0 && errno == EINTR);

  if (sent < 0) return -1;
  if ((size_t)sent != UAV_PROTO_HEADER_SIZE + wire_length) {
    errno = EIO;
    return -1;
  }
  return 0;
}

int uav_proto_seqpacket_receive(int fd, uint32_t magic, uint16_t version,
                                uint16_t expected_kind,
                                struct uav_proto_msg* msg,
                                struct ucred* credentials) {
  uint8_t header[UAV_PROTO_HEADER_SIZE];
  union {
    struct cmsghdr align;
    uint8_t bytes[CMSG_SPACE(sizeof(struct ucred))];
  } control;
  struct iovec iov[2];
  struct msghdr message;
  struct cmsghdr* cmsg;
  uint32_t wire_length;
  ssize_t received;
  int found_credentials = 0;

  if (fd < 0 || msg == NULL) {
    errno = EINVAL;
    return -1;
  }

  for (;;) {
    memset(&message, 0, sizeof(message));
    memset(&control, 0, sizeof(control));
    iov[0] = (struct iovec){.iov_base = header, .iov_len = sizeof(header)};
    iov[1] =
        (struct iovec){.iov_base = msg->payload, .iov_len = sizeof(msg->payload)};
    message.msg_iov = iov;
    message.msg_iovlen = 2;
    if (credentials != NULL) {
      message.msg_control = control.bytes;
      message.msg_controllen = sizeof(control.bytes);
    }

    received = recvmsg(fd, &message, 0);
    if (received < 0 && errno == EINTR) continue;
    break;
  }

  if (received < 0) return -1;
  if (received == 0) {
    errno = ECONNRESET;
    return -1;
  }
  if (message.msg_flags & MSG_TRUNC) {
    errno = EMSGSIZE;
    return -1;
  }
  if (message.msg_flags & MSG_CTRUNC) {
    errno = EPROTO;
    return -1;
  }
  if ((size_t)received < UAV_PROTO_HEADER_SIZE) {
    errno = EPROTO;
    return -1;
  }

  if (uav_proto_decode_header(header, magic, version, expected_kind, &msg->type,
                              &wire_length) < 0)
    return -1;
  if ((size_t)received != UAV_PROTO_HEADER_SIZE + wire_length) {
    errno = EPROTO;
    return -1;
  }

  if (credentials != NULL) {
    for (cmsg = CMSG_FIRSTHDR(&message); cmsg != NULL;
         cmsg = CMSG_NXTHDR(&message, cmsg)) {
      if (cmsg->cmsg_level == SOL_SOCKET &&
          cmsg->cmsg_type == SCM_CREDENTIALS &&
          cmsg->cmsg_len >= CMSG_LEN(sizeof(*credentials))) {
        memcpy(credentials, CMSG_DATA(cmsg), sizeof(*credentials));
        found_credentials = 1;
        break;
      }
    }
    if (!found_credentials) {
      errno = EPROTO;
      return -1;
    }
  }

  return uav_proto_finish_receive(msg, expected_kind, wire_length);
}
