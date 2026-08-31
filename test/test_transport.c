#include <errno.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <unistd.h>

#include "transport.h"
#include "uav_test.h"

struct mock_transport_ctx {
  const unsigned char* input;
  size_t input_size;
  size_t input_offset;
  unsigned char output[16];
  size_t output_size;
  int interrupt_read;
  int interrupt_write;
  int stall_read;
  int stall_write;
};

static ssize_t mock_read(void* ptr, void* buf, size_t size) {
  struct mock_transport_ctx* ctx = ptr;
  size_t available;

  if (ctx->interrupt_read) {
    ctx->interrupt_read = 0;
    errno = EINTR;
    return -1;
  }

  if (ctx->stall_read) return 0;

  available = ctx->input_size - ctx->input_offset;
  if (size > available) size = available;
  if (size > 2) size = 2;

  memcpy(buf, ctx->input + ctx->input_offset, size);
  ctx->input_offset += size;
  return (ssize_t)size;
}

static ssize_t mock_write(void* ptr, const void* buf, size_t size) {
  struct mock_transport_ctx* ctx = ptr;

  if (ctx->interrupt_write) {
    ctx->interrupt_write = 0;
    errno = EINTR;
    return -1;
  }

  if (ctx->stall_write) return 0;

  if (size > 2) size = 2;

  memcpy(ctx->output + ctx->output_size, buf, size);
  ctx->output_size += size;
  return (ssize_t)size;
}

static const struct uav_transport_ops mock_transport_ops = {
    .read = mock_read,
    .write = mock_write,
    .destroy = NULL,
};

TEST(test_transport_partial_io) {
  static const unsigned char data[] = "transport";
  struct mock_transport_ctx ctx = {
      .input = data,
      .input_size = sizeof(data),
      .interrupt_read = 1,
      .interrupt_write = 1,
  };
  struct uav_transport transport = {
      .ops = &mock_transport_ops,
      .ctx = &ctx,
  };
  unsigned char received[sizeof(data)];

  TEST_ASSERT_EQ(
      0, uav_transport_read_all(&transport, received, sizeof(received)));
  TEST_ASSERT_EQ(0, memcmp(data, received, sizeof(data)));

  TEST_ASSERT_EQ(0, uav_transport_write_all(&transport, data, sizeof(data)));
  TEST_ASSERT_EQ(sizeof(data), ctx.output_size);
  TEST_ASSERT_EQ(0, memcmp(data, ctx.output, sizeof(data)));
  return 0;
}

TEST(test_transport_no_progress) {
  struct mock_transport_ctx ctx = {
      .stall_read = 1,
      .stall_write = 1,
  };
  struct uav_transport transport = {
      .ops = &mock_transport_ops,
      .ctx = &ctx,
  };
  unsigned char byte;

  TEST_ASSERT_EQ(-1, uav_transport_read_all(&transport, &byte, 1));
  TEST_ASSERT_EQ(ECONNRESET, errno);
  TEST_ASSERT_EQ(-1, uav_transport_write_all(&transport, &byte, 1));
  TEST_ASSERT_EQ(EIO, errno);
  return 0;
}

TEST(test_transport_invalid_arguments) {
  struct uav_transport transport = {
      .ops = &mock_transport_ops,
      .ctx = NULL,
  };
  unsigned char byte;

  TEST_ASSERT_EQ(-1, uav_transport_read_all(NULL, &byte, 1));
  TEST_ASSERT_EQ(EINVAL, errno);
  TEST_ASSERT_EQ(-1, uav_transport_write_all(&transport, NULL, 1));
  TEST_ASSERT_EQ(EINVAL, errno);
  TEST_ASSERT_EQ(0, uav_transport_write_all(&transport, NULL, 0));
  TEST_ASSERT_NULL(uav_fd_transport_create(-1));
  TEST_ASSERT_EQ(EINVAL, errno);
  return 0;
}

TEST(test_fd_transport_ownership) {
  struct uav_transport* transport;
  int fds[2];

  TEST_ASSERT_EQ(0, pipe(fds));
  transport = uav_fd_transport_create(fds[0]);
  TEST_ASSERT_NOT_NULL(transport);

  uav_transport_destroy(&transport);
  TEST_ASSERT_NULL(transport);
  TEST_ASSERT_EQ(-1, fcntl(fds[0], F_GETFD));
  TEST_ASSERT_EQ(EBADF, errno);

  uav_transport_destroy(&transport);
  close(fds[1]);
  return 0;
}

TEST(test_fd_transport_closed_peer) {
  struct uav_transport* transport;
  unsigned char byte = 0;
  int fds[2];

  TEST_ASSERT_EQ(0, socketpair(AF_UNIX, SOCK_STREAM, 0, fds));
  transport = uav_fd_transport_create(fds[0]);
  TEST_ASSERT_NOT_NULL(transport);
  close(fds[1]);

  TEST_ASSERT_EQ(-1, uav_transport_write_all(transport, &byte, 1));
  TEST_ASSERT_EQ(EPIPE, errno);
  uav_transport_destroy(&transport);
  return 0;
}

int main(void) {
  TEST_SUITE("Transport");

  RUN_TEST(test_transport_partial_io);
  RUN_TEST(test_transport_no_progress);
  RUN_TEST(test_transport_invalid_arguments);
  RUN_TEST(test_fd_transport_ownership);
  RUN_TEST(test_fd_transport_closed_peer);

  return uav_test_report();
}
