#include "transport.h"

#include <errno.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <unistd.h>

#include "utils.h"

static ssize_t fd_read(void* ctx, void* buf, size_t size);
static ssize_t fd_write(void* ctx, const void* buf, size_t size);
static void fd_destroy(void* ctx);

struct uav_fd_transport_ctx {
  int fd;
};

static const struct uav_transport_ops fd_transport_ops = {
    .read = fd_read, .write = fd_write, .destroy = fd_destroy};

struct uav_transport* uav_fd_transport_create(int fd) {
  struct uav_fd_transport_ctx* ctx;
  struct uav_transport* transport;

  if (fd < 0) {
    errno = EINVAL;
    return NULL;
  }

  transport = uav_malloc(sizeof(*transport));
  ctx = uav_malloc(sizeof(*ctx));

  ctx->fd = fd;

  transport->ops = &fd_transport_ops;
  transport->ctx = ctx;

  return transport;
}

static ssize_t fd_read(void* ctx, void* buf, size_t size) {
  struct uav_fd_transport_ctx* fd_ctx = ctx;

  return read(fd_ctx->fd, buf, size);
}

static ssize_t fd_write(void* ctx, const void* buf, size_t size) {
  struct uav_fd_transport_ctx* fd_ctx = ctx;
  ssize_t ret;

  ret = send(fd_ctx->fd, buf, size, MSG_NOSIGNAL);
  if (ret < 0 && errno == ENOTSOCK) ret = write(fd_ctx->fd, buf, size);

  return ret;
}

static void fd_destroy(void* ctx) {
  struct uav_fd_transport_ctx* fd_ctx = ctx;

  if (fd_ctx->fd >= 0) close(fd_ctx->fd);

  free(fd_ctx);
}

void uav_transport_destroy(struct uav_transport** transport) {
  if (transport == NULL || *transport == NULL) return;

  if ((*transport)->ops != NULL && (*transport)->ops->destroy != NULL)
    (*transport)->ops->destroy((*transport)->ctx);

  free(*transport);
  *transport = NULL;
}

int uav_transport_write_all(struct uav_transport* transport, const void* buf,
                            size_t size) {
  const unsigned char* p = buf;

  if (transport == NULL || transport->ops == NULL ||
      transport->ops->write == NULL || (buf == NULL && size > 0)) {
    errno = EINVAL;
    return -1;
  }

  while (size > 0) {
    ssize_t n = transport->ops->write(transport->ctx, p, size);

    if (n < 0) {
      if (errno == EINTR) continue;
      return -1;
    }

    if (n == 0) {
      errno = EIO;
      return -1;
    }

    if ((size_t)n > size) {
      errno = EIO;
      return -1;
    }

    p += n;
    size -= (size_t)n;
  }

  return 0;
}

int uav_transport_read_all(struct uav_transport* transport, void* buf,
                           size_t size) {
  unsigned char* p = buf;

  if (transport == NULL || transport->ops == NULL ||
      transport->ops->read == NULL || (buf == NULL && size > 0)) {
    errno = EINVAL;
    return -1;
  }

  while (size > 0) {
    ssize_t n = transport->ops->read(transport->ctx, p, size);

    if (n < 0) {
      if (errno == EINTR) continue;
      return -1;
    }

    if (n == 0) {
      errno = ECONNRESET;
      return -1;
    }

    if ((size_t)n > size) {
      errno = EIO;
      return -1;
    }

    p += n;
    size -= (size_t)n;
  }

  return 0;
}
