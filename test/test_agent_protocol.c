#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

#include "agent_protocol.h"
#include "transport.h"
#include "uav_test.h"
#include "utils.h"

struct test_transport_ctx {
  int fd;
};

static ssize_t test_read(void* ptr, void* buf, size_t size) {
  struct test_transport_ctx* ctx = ptr;

  return read(ctx->fd, buf, size);
}

static ssize_t test_write(void* ptr, const void* buf, size_t size) {
  struct test_transport_ctx* ctx = ptr;

  return write(ctx->fd, buf, size);
}

static const struct uav_transport_ops test_transport_ops = {
    .read = test_read,
    .write = test_write,
    .destroy = NULL,
};

static int receive_upload(int fd, const uint8_t* expected, size_t size) {
  struct test_transport_ctx ctx = {.fd = fd};
  struct uav_transport transport = {
      .ops = &test_transport_ops,
      .ctx = &ctx,
  };
  struct uav_proto_msg msg;
  struct uav_upload_meta meta;
  uint8_t received[UAV_PROTO_MAX_CHUNK + 257];
  FILE* file;
  int ret = 1;

  file = tmpfile();
  if (file == NULL) goto out;

  if (uav_proto_recv(&transport, &msg) < 0) goto close_file;
  if (uav_proto_decode_upload_begin(&msg, &meta) < 0) goto close_file;
  if (meta.size != size || meta.source_mode != 0751 ||
      meta.purpose != UAV_UPLOAD_EXECUTABLE)
    goto close_file;

  if (uav_proto_accept_upload(&transport) < 0) goto close_file;
  if (uav_proto_receive_upload(&transport, fileno(file), meta.size) < 0)
    goto close_file;

  if (lseek(fileno(file), 0, SEEK_SET) < 0) goto close_file;
  if (read(fileno(file), received, sizeof(received)) != (ssize_t)size)
    goto close_file;
  if (memcmp(received, expected, size) != 0) goto close_file;

  if (uav_proto_complete_upload(&transport) < 0) goto close_file;
  ret = 0;

close_file:
  fclose(file);
out:
  close(fd);
  return ret;
}

TEST(test_protocol_status_messages) {
  struct test_transport_ctx first_ctx;
  struct test_transport_ctx second_ctx;
  struct uav_transport first = {
      .ops = &test_transport_ops,
      .ctx = &first_ctx,
  };
  struct uav_transport second = {
      .ops = &test_transport_ops,
      .ctx = &second_ctx,
  };
  struct uav_proto_msg msg;
  int fds[2];
  int value;

  TEST_ASSERT_EQ(0, socketpair(AF_UNIX, SOCK_STREAM, 0, fds));
  first_ctx.fd = fds[0];
  second_ctx.fd = fds[1];

  TEST_ASSERT_MSG(uav_proto_send_error(&first, EACCES) == 0, strerror(errno));
  TEST_ASSERT_EQ(0, uav_proto_recv(&second, &msg));
  TEST_ASSERT_EQ(0, uav_proto_decode_error(&msg, &value));
  TEST_ASSERT_EQ(EACCES, value);

  TEST_ASSERT_EQ(0, uav_proto_send_exit(&second, 42));
  TEST_ASSERT_EQ(0, uav_proto_recv(&first, &msg));
  TEST_ASSERT_EQ(0, uav_proto_decode_exit(&msg, &value));
  TEST_ASSERT_EQ(42, value);

  close(fds[0]);
  close(fds[1]);
  return 0;
}

TEST(test_protocol_rejects_bad_typed_payload) {
  struct uav_proto_msg msg = {
      .type = UAV_MSG_UPLOAD_BEGIN,
      .length = 1,
  };
  struct uav_upload_meta meta;

  TEST_ASSERT_EQ(-1, uav_proto_decode_upload_begin(&msg, &meta));
  TEST_ASSERT_EQ(EPROTO, errno);
  TEST_ASSERT_EQ(-1, uav_proto_decode_exit(&msg, &(int){0}));
  TEST_ASSERT_EQ(EPROTO, errno);
  return 0;
}

TEST(test_protocol_streamed_upload) {
  uint8_t data[UAV_PROTO_MAX_CHUNK + 257];
  struct test_transport_ctx ctx;
  struct uav_transport transport = {
      .ops = &test_transport_ops,
      .ctx = &ctx,
  };
  struct uav_upload_meta meta = {
      .size = sizeof(data),
      .source_mode = 0751,
      .purpose = UAV_UPLOAD_EXECUTABLE,
  };
  FILE* source;
  pid_t child;
  int fds[2];
  int status;

  for (size_t i = 0; i < sizeof(data); ++i) data[i] = (uint8_t)i;

  source = tmpfile();
  TEST_ASSERT_NOT_NULL(source);
  TEST_ASSERT_EQ(0, uav_fd_write_all(fileno(source), data, sizeof(data)));
  TEST_ASSERT_EQ(0, lseek(fileno(source), 0, SEEK_SET));
  TEST_ASSERT_EQ(0, socketpair(AF_UNIX, SOCK_STREAM, 0, fds));

  child = fork();
  TEST_ASSERT(child >= 0);
  if (child == 0) {
    fclose(source);
    close(fds[0]);
    _exit(receive_upload(fds[1], data, sizeof(data)));
  }

  close(fds[1]);
  ctx.fd = fds[0];
  TEST_ASSERT_MSG(uav_proto_upload(&transport, fileno(source), &meta) == 0,
                  strerror(errno));
  TEST_ASSERT_EQ(child, waitpid(child, &status, 0));
  TEST_ASSERT(WIFEXITED(status));
  TEST_ASSERT_EQ(0, WEXITSTATUS(status));

  close(fds[0]);
  fclose(source);
  return 0;
}

int main(void) {
  TEST_SUITE("Protocol");

  RUN_TEST(test_protocol_status_messages);
  RUN_TEST(test_protocol_rejects_bad_typed_payload);
  RUN_TEST(test_protocol_streamed_upload);

  return uav_test_report();
}
