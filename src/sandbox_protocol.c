#include <arpa/inet.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>

#include "sandbox_protocol.h"
#include "utils.h"

int uav_sandbox_proto_send(int fd, uint16_t type, const void *payload, uint32_t length) {
  unsigned char buf[12];
  int ret;

  if(length > UAV_SANDBOX_PROTO_MAX_PAYLOAD) {
    errno = EMSGSIZE;
    return -1;
  }

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

int uav_sandbox_proto_upload(int fd, char *path, size_t path_size, const uint8_t *data, size_t size) {
  int ret = -1;
  size_t off = 0, chunk_size = size - off;
  uint32_t sz;
  struct uav_sandbox_proto_msg msg;

  if (!path || path_size == 0 || !data || size == 0 || size > UINT32_MAX) {
    errno = EINVAL;
    return -1;
  }

  sz = htonl(size);
  ret = uav_sandbox_proto_send(fd, UAV_SANDBOX_MSG_UPLOAD_BEGIN, &sz, sizeof(uint32_t));
  if (ret < 0) return ret;

  ret = uav_sandbox_proto_recv(fd, &msg);
  if (ret < 0) return ret;
  if (msg.type != UAV_SANDBOX_MSG_STR || msg.length == 0 ||
      msg.length > path_size || msg.payload[msg.length - 1] != '\0') {
    errno = EPROTO;
    return -1;
  }
  memcpy(path, msg.payload, msg.length);

  while (off < size) {
    chunk_size = size - off;
    if (chunk_size > UAV_SANDBOX_PROTO_MAX_CHUNK) chunk_size = UAV_SANDBOX_PROTO_MAX_CHUNK;

    ret =  uav_sandbox_proto_send(fd, UAV_SANDBOX_MSG_UPLOAD_CHUNK, data + off, chunk_size);
    if (ret < 0) return ret;

    off += chunk_size;
  }

  return uav_sandbox_proto_send(fd, UAV_SANDBOX_MSG_UPLOAD_END, NULL, 0);
}

int uav_sandbox_proto_download(int fd, const struct uav_sandbox_proto_msg *begin, const char *path, uint8_t **data, size_t *size) {

  struct uav_sandbox_proto_msg msg;
  int ret;
  uint32_t sz;
  size_t off = 0;
  uint8_t *buf = NULL;

  if (begin == NULL || path == NULL || data == NULL || size == NULL) {
    errno = EINVAL;
    return -1;
  }

  if (begin->type != UAV_SANDBOX_MSG_UPLOAD_BEGIN ||
      begin->length != sizeof(uint32_t)) {
    errno = EPROTO;
    return -1;
  }

  ret = uav_sandbox_proto_send(fd, UAV_SANDBOX_MSG_STR, (const uint8_t *) path, strlen(path) + 1);
  if (ret < 0) return ret;

  memcpy(&sz, begin->payload, sizeof(sz));
  sz = ntohl(sz);
  buf = uav_malloc(sz);

  while (off < sz) {
    ret = uav_sandbox_proto_recv(fd, &msg);
    if (ret < 0) {
      free(buf);
      return -1;
    }

    if (msg.type != UAV_SANDBOX_MSG_UPLOAD_CHUNK || msg.length == 0 ||
        msg.length > (sz - off)) {
      errno = EPROTO;
      free(buf);
      return -1;
    }

    memcpy(buf + off, msg.payload, msg.length);
    off += msg.length;
  }

  ret = uav_sandbox_proto_recv(fd, &msg);
  if (ret < 0) {
    free(buf);
    return -1;
  }

  if (msg.type != UAV_SANDBOX_MSG_UPLOAD_END || msg.length != 0) {
    errno = EPROTO;
    free(buf);
    return -1;
  }
  *data = buf;
  *size = sz;
  return 0;
}
