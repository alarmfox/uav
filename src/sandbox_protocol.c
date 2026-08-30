#include <arpa/inet.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>

#include "sandbox_protocol.h"

static int uav_write_all(int fd, const void *buf, size_t len);
static int uav_read_all(int fd, void *buf, size_t len);

int uav_sandbox_proto_send(int fd, uint16_t type, const void *payload, uint32_t length) {
  unsigned char buf[12];
  int ret;

  uint32_t magic = htonl(UAV_SANDBOX_PROTO_MAGIC);
  uint16_t ver   = htons(UAV_SANDBOX_PROTO_VERSION);
  uint16_t typ   = htons(type);
  uint32_t len   = htonl(length);

  memcpy(buf + 0, &magic, sizeof(magic));
  memcpy(buf + 4, &ver,   sizeof(ver));
  memcpy(buf + 6, &typ,   sizeof(typ));
  memcpy(buf + 8, &len,   sizeof(len));

  ret = uav_write_all(fd, buf, sizeof(buf));
  if (ret < 0) return ret;

  if (length > 0) {
    if (payload == NULL) {
      errno = EINVAL;
      return -1;
    }

    ret = uav_write_all(fd, payload, length);
    if(ret < 0) return ret;
  }

  return 0;
}

int uav_sandbox_proto_recv(int fd, struct uav_sandbox_proto_msg *msg) {
  unsigned char buf[12];
  int ret;

  uint32_t magic;
  uint16_t version;
  uint16_t type;
  uint32_t length;

  ret = uav_read_all(fd, buf, sizeof(buf));

  if(ret < 0) return ret;

  memcpy(&magic,   buf + 0, 4);
  memcpy(&version, buf + 4, 2);
  memcpy(&type,    buf + 6, 2);
  memcpy(&length,  buf + 8, 4);

  msg->magic   = ntohl(magic);
  msg->version = ntohs(version);
  msg->type    = ntohs(type);
  msg->length  = ntohl(length);

  if (msg->magic != UAV_SANDBOX_PROTO_MAGIC) {
    errno = EPROTO;
    return -1;
  }

  if (msg->version != UAV_SANDBOX_PROTO_VERSION) {
    errno = EPROTO;
    return -1;
  }

  if (msg->length > sizeof(msg->payload)) {
    errno = EMSGSIZE;
    return -1;
  }

  return msg->length > 0 ? ret = uav_read_all(fd, msg->payload, msg->length) : 0;
}

static int uav_write_all(int fd, const void *buf, size_t len) {
  const unsigned char *p = buf;

  while (len > 0) {
    ssize_t n = write(fd, p, len);

    if (n < 0) {
      if (errno == EINTR)
        continue;

      return -1;
    }

    if (n == 0) {
      errno = EIO;
      return -1;
    }

    p += n;
    len -= (size_t)n;
  }

  return 0;
}

static int uav_read_all(int fd, void *buf, size_t len) {
  unsigned char *p = buf;

  while (len > 0) {
    ssize_t n = read(fd, p, len);

    if (n < 0) {
      if (errno == EINTR)
        continue;

      return -1;
    }

    if (n == 0) {
      errno = ECONNRESET;
      return -1;
    }

    p += n;
    len -= (size_t)n;
  }

  return 0;
}
