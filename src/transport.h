#ifndef UAV_SANDBOX_TRANSPORT_H
#define UAV_SANDBOX_TRANSPORT_H

#include <stddef.h>
#include <sys/types.h>

struct uav_transport_ops {
  ssize_t (*read)(void* ctx, void* buf, size_t size);
  ssize_t (*write)(void* ctx, const void* buf, size_t size);
  void (*destroy)(void* ctx);
};

struct uav_transport {
  const struct uav_transport_ops* ops;
  void* ctx;
};

struct uav_transport* uav_fd_transport_create(int fd);
void uav_transport_destroy(struct uav_transport** transport);
int uav_transport_read_all(struct uav_transport* transport, void* buf,
                           size_t size);
int uav_transport_write_all(struct uav_transport* transport, const void* buf,
                            size_t size);

#endif  // !UAV_SANDBOX_TRANSPORT_H
