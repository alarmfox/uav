#include <errno.h>
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "agent_protocol.h"
#include "daemon_protocol.h"
#include "protocol_utils.h"
#include "transport.h"
#include "uav_test.h"

struct test_transport_ctx {
  int fd;
  int fail_write;
};

static ssize_t test_read(void* ptr, void* buf, size_t size) {
  struct test_transport_ctx* ctx = ptr;

  return read(ctx->fd, buf, size);
}

static ssize_t test_write(void* ptr, const void* buf, size_t size) {
  struct test_transport_ctx* ctx = ptr;

  if (ctx->fail_write) {
    errno = EIO;
    return -1;
  }

  return write(ctx->fd, buf, size);
}

static const struct uav_transport_ops test_transport_ops = {
    .read = test_read,
    .write = test_write,
    .destroy = NULL,
};

TEST(test_daemon_protocol_round_trip) {
  static const uint8_t payload[] = {1, 2, 3, 4};
  struct test_transport_ctx sender_ctx = {.fd = -1};
  struct test_transport_ctx receiver_ctx = {.fd = -1};
  struct uav_transport sender = {
      .ops = &test_transport_ops,
      .ctx = &sender_ctx,
  };
  struct uav_transport receiver = {
      .ops = &test_transport_ops,
      .ctx = &receiver_ctx,
  };
  struct uav_proto_msg msg;
  int fds[2];

  TEST_ASSERT_EQ(0, socketpair(AF_UNIX, SOCK_STREAM, 0, fds));
  sender_ctx.fd = fds[0];
  receiver_ctx.fd = fds[1];

  TEST_ASSERT_MSG(uav_daemon_proto_send(&sender, UAV_DAEMON_MSG_ATTACH_SELF,
                                        payload, sizeof(payload)) == 0,
                  strerror(errno));
  TEST_ASSERT_EQ(0, uav_daemon_proto_recv(&receiver, &msg));
  TEST_ASSERT_EQ(UAV_DAEMON_PROTO_MAGIC, msg.header.magic);
  TEST_ASSERT_EQ(UAV_DAEMON_PROTO_VERSION, msg.header.version);
  TEST_ASSERT_EQ(UAV_DAEMON_MSG_ATTACH_SELF, msg.header.type);
  TEST_ASSERT_EQ(sizeof(payload), msg.header.length);
  TEST_ASSERT_EQ(0, memcmp(payload, msg.payload, sizeof(payload)));

  TEST_ASSERT_EQ(
      0, uav_daemon_proto_send(&receiver, UAV_DAEMON_MSG_HELLO, NULL, 0));
  TEST_ASSERT_EQ(0, uav_daemon_proto_recv(&sender, &msg));
  TEST_ASSERT_EQ(UAV_DAEMON_PROTO_MAGIC, msg.header.magic);
  TEST_ASSERT_EQ(UAV_DAEMON_PROTO_VERSION, msg.header.version);
  TEST_ASSERT_EQ(UAV_DAEMON_MSG_HELLO, msg.header.type);
  TEST_ASSERT_EQ(0, msg.header.length);

  close(fds[0]);
  close(fds[1]);
  return 0;
}

TEST(test_protocols_reject_each_other) {
  struct test_transport_ctx first_ctx = {.fd = -1};
  struct test_transport_ctx second_ctx = {.fd = -1};
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

  TEST_ASSERT_EQ(0, socketpair(AF_UNIX, SOCK_STREAM, 0, fds));
  first_ctx.fd = fds[0];
  second_ctx.fd = fds[1];

  TEST_ASSERT_MSG(
      uav_agent_proto_send(&first, UAV_AGENT_MSG_HELLO, NULL, 0) == 0,
      strerror(errno));
  TEST_ASSERT_EQ(-1, uav_daemon_proto_recv(&second, &msg));
  TEST_ASSERT_EQ(EPROTO, errno);

  TEST_ASSERT_EQ(0,
                 uav_daemon_proto_send(&second, UAV_DAEMON_MSG_HELLO, NULL, 0));
  TEST_ASSERT_EQ(-1, uav_agent_proto_recv(&first, &msg));
  TEST_ASSERT_EQ(EPROTO, errno);

  close(fds[0]);
  close(fds[1]);
  return 0;
}

TEST(test_protocol_frame_validation) {
  struct test_transport_ctx first_ctx = {.fd = -1};
  struct test_transport_ctx second_ctx = {.fd = -1};
  struct uav_transport first = {
      .ops = &test_transport_ops,
      .ctx = &first_ctx,
  };
  struct uav_transport second = {
      .ops = &test_transport_ops,
      .ctx = &second_ctx,
  };
  struct uav_proto_msg msg;
  uint8_t byte = 0;
  int fds[2];

  TEST_ASSERT_EQ(0, socketpair(AF_UNIX, SOCK_STREAM, 0, fds));
  first_ctx.fd = fds[0];
  second_ctx.fd = fds[1];

  TEST_ASSERT_MSG(uav_proto_send_frame(&first, UAV_DAEMON_PROTO_MAGIC,
                                       UAV_DAEMON_PROTO_VERSION + 1,
                                       UAV_DAEMON_MSG_HELLO, NULL, 0) == 0,
                  strerror(errno));
  TEST_ASSERT_EQ(-1, uav_daemon_proto_recv(&second, &msg));
  TEST_ASSERT_EQ(EPROTO, errno);

  TEST_ASSERT_EQ(
      -1, uav_proto_send_frame(&first, UAV_DAEMON_PROTO_MAGIC,
                               UAV_DAEMON_PROTO_VERSION, UAV_DAEMON_MSG_HELLO,
                               &byte, UAV_PROTO_MAX_PAYLOAD + 1));
  TEST_ASSERT_EQ(EMSGSIZE, errno);

  close(fds[0]);
  close(fds[1]);
  return 0;
}

TEST(test_protocol_reports_transport_failure) {
  struct test_transport_ctx ctx = {.fd = -1, .fail_write = 1};
  struct uav_transport transport = {
      .ops = &test_transport_ops,
      .ctx = &ctx,
  };

  TEST_ASSERT_EQ(
      -1, uav_daemon_proto_send(&transport, UAV_DAEMON_MSG_HELLO, NULL, 0));
  TEST_ASSERT_EQ(EIO, errno);
  return 0;
}

int main(void) {
  TEST_SUITE("Daemon protocol");

  RUN_TEST(test_daemon_protocol_round_trip);
  RUN_TEST(test_protocols_reject_each_other);
  RUN_TEST(test_protocol_frame_validation);
  RUN_TEST(test_protocol_reports_transport_failure);

  return uav_test_report();
}
