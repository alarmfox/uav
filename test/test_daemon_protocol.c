#include <errno.h>
#include <limits.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

#include "agent_protocol.h"
#include "daemon_protocol.h"
#include "protocol_utils.h"
#include "uav_test.h"

#define TEST_HEADER_SIZE 16U

static int enable_passcred(int fd) {
  int enabled = 1;

  return setsockopt(fd, SOL_SOCKET, SO_PASSCRED, &enabled, sizeof(enabled));
}

static void make_header(uint8_t header[TEST_HEADER_SIZE], uint32_t magic,
                        uint16_t version, uint16_t kind, uint16_t type,
                        uint16_t reserved, uint32_t length) {
  memset(header, 0, TEST_HEADER_SIZE);
  uav_proto_put_u32(header, magic);
  uav_proto_put_u16(header + 4, version);
  uav_proto_put_u16(header + 6, kind);
  uav_proto_put_u16(header + 8, type);
  uav_proto_put_u16(header + 10, reserved);
  uav_proto_put_u32(header + 12, length);
}

TEST(test_daemon_protocol_request_response) {
  static const uint8_t payload[] = {1, 2, 3, 4};
  struct uav_proto_msg msg;
  struct ucred credentials;
  int fds[2];

  TEST_ASSERT_EQ(0, socketpair(AF_UNIX, SOCK_SEQPACKET, 0, fds));
  TEST_ASSERT_EQ(0, enable_passcred(fds[1]));
  TEST_ASSERT_EQ(
      0, uav_daemon_proto_send_request(fds[0], UAV_DAEMON_MSG_REGISTER_WORKLOAD,
                                       payload, sizeof(payload)));
  TEST_ASSERT_EQ(0,
                 uav_daemon_proto_receive_request(fds[1], &msg, &credentials));
  TEST_ASSERT_EQ(UAV_DAEMON_MSG_REGISTER_WORKLOAD, msg.type);
  TEST_ASSERT_EQ(0, msg.error);
  TEST_ASSERT_EQ(sizeof(payload), msg.length);
  TEST_ASSERT_EQ(0, memcmp(payload, msg.payload, sizeof(payload)));
  TEST_ASSERT_EQ(getpid(), credentials.pid);
  TEST_ASSERT_EQ(getuid(), credentials.uid);
  TEST_ASSERT_EQ(getgid(), credentials.gid);

  TEST_ASSERT_EQ(
      0, uav_daemon_proto_send_response(fds[1], UAV_DAEMON_MSG_REGISTER_WORKLOAD,
                                        EBUSY, payload, sizeof(payload)));
  TEST_ASSERT_EQ(0, uav_daemon_proto_receive_response(
                        fds[0], UAV_DAEMON_MSG_REGISTER_WORKLOAD, &msg));
  TEST_ASSERT_EQ(EBUSY, msg.error);
  TEST_ASSERT_EQ(sizeof(payload), msg.length);
  TEST_ASSERT_EQ(0, memcmp(payload, msg.payload, sizeof(payload)));

  close(fds[0]);
  close(fds[1]);
  return 0;
}

TEST(test_daemon_protocol_listener_credentials_are_race_free) {
  struct sockaddr_un address;
  struct uav_proto_msg msg;
  struct ucred credentials;
  socklen_t address_length;
  int accepted = -1;
  int client = -1;
  int listener = -1;
  int name_length;

  listener = socket(AF_UNIX, SOCK_SEQPACKET, 0);
  TEST_ASSERT(listener >= 0);
  TEST_ASSERT_EQ(0, enable_passcred(listener));

  memset(&address, 0, sizeof(address));
  address.sun_family = AF_UNIX;
  name_length = snprintf(address.sun_path + 1, sizeof(address.sun_path) - 1,
                         "uav-protocol-test-%d", getpid());
  TEST_ASSERT(name_length > 0);
  TEST_ASSERT((size_t)name_length < sizeof(address.sun_path) - 1);
  address_length = (socklen_t)(offsetof(struct sockaddr_un, sun_path) + 1 +
                               (size_t)name_length);

  TEST_ASSERT_EQ(
      0, bind(listener, (const struct sockaddr*)&address, address_length));
  TEST_ASSERT_EQ(0, listen(listener, 1));

  client = socket(AF_UNIX, SOCK_SEQPACKET, 0);
  TEST_ASSERT(client >= 0);
  TEST_ASSERT_EQ(
      0, connect(client, (const struct sockaddr*)&address, address_length));
  TEST_ASSERT_EQ(0, uav_daemon_proto_send_request(
                        client, UAV_DAEMON_MSG_REGISTER_WORKLOAD, NULL, 0));

  accepted = accept(listener, NULL, NULL);
  TEST_ASSERT(accepted >= 0);
  TEST_ASSERT_EQ(
      0, uav_daemon_proto_receive_request(accepted, &msg, &credentials));
  TEST_ASSERT_EQ(getpid(), credentials.pid);

  close(accepted);
  close(client);
  close(listener);
  return 0;
}

TEST(test_daemon_protocol_credentials_follow_sender) {
  struct uav_proto_msg msg;
  struct ucred credentials;
  int fds[2];
  int status;
  pid_t child;

  TEST_ASSERT_EQ(0, socketpair(AF_UNIX, SOCK_SEQPACKET, 0, fds));
  TEST_ASSERT_EQ(0, enable_passcred(fds[0]));

  child = fork();
  TEST_ASSERT(child >= 0);
  if (child == 0) {
    close(fds[0]);
    _exit(uav_daemon_proto_send_request(
              fds[1], UAV_DAEMON_MSG_REGISTER_WORKLOAD, NULL, 0) == 0
              ? 0
              : 1);
  }

  close(fds[1]);
  TEST_ASSERT_EQ(0,
                 uav_daemon_proto_receive_request(fds[0], &msg, &credentials));
  TEST_ASSERT_EQ(UAV_DAEMON_MSG_REGISTER_WORKLOAD, msg.type);
  TEST_ASSERT_EQ(child, credentials.pid);
  TEST_ASSERT_EQ(child, waitpid(child, &status, 0));
  TEST_ASSERT(WIFEXITED(status));
  TEST_ASSERT_EQ(0, WEXITSTATUS(status));

  close(fds[0]);
  return 0;
}

TEST(test_daemon_protocol_rejects_wrong_response_type) {
  struct uav_proto_msg msg;
  int fds[2];

  TEST_ASSERT_EQ(0, socketpair(AF_UNIX, SOCK_SEQPACKET, 0, fds));
  TEST_ASSERT_EQ(0, uav_daemon_proto_send_response(
                        fds[0], UAV_DAEMON_MSG_REGISTER_WORKLOAD, 0, NULL, 0));
  TEST_ASSERT_EQ(-1, uav_daemon_proto_receive_response(
                         fds[1], UAV_DAEMON_MSG_TEARDOWN_WORKLOAD, &msg));
  TEST_ASSERT_EQ(EPROTO, errno);

  close(fds[0]);
  close(fds[1]);
  return 0;
}

TEST(test_daemon_protocol_rejects_invalid_frames) {
  uint8_t header[TEST_HEADER_SIZE];
  struct uav_proto_msg msg;
  struct ucred credentials;
  int fds[2];

  TEST_ASSERT_EQ(0, socketpair(AF_UNIX, SOCK_SEQPACKET, 0, fds));
  TEST_ASSERT_EQ(0, enable_passcred(fds[1]));

  TEST_ASSERT_EQ(
      0, uav_proto_seqpacket_send(
             fds[0], UAV_DAEMON_PROTO_MAGIC, UAV_DAEMON_PROTO_VERSION + 1,
             UAV_PROTO_REQUEST, UAV_DAEMON_MSG_REGISTER_WORKLOAD, 0, NULL, 0));
  TEST_ASSERT_EQ(-1,
                 uav_daemon_proto_receive_request(fds[1], &msg, &credentials));
  TEST_ASSERT_EQ(EPROTO, errno);

  make_header(header, UAV_DAEMON_PROTO_MAGIC, UAV_DAEMON_PROTO_VERSION,
              UAV_PROTO_REQUEST, UAV_DAEMON_MSG_REGISTER_WORKLOAD, 1, 0);
  TEST_ASSERT_EQ(TEST_HEADER_SIZE,
                 send(fds[0], header, sizeof(header), MSG_NOSIGNAL));
  TEST_ASSERT_EQ(-1,
                 uav_daemon_proto_receive_request(fds[1], &msg, &credentials));
  TEST_ASSERT_EQ(EPROTO, errno);

  make_header(header, UAV_DAEMON_PROTO_MAGIC, UAV_DAEMON_PROTO_VERSION,
              UAV_PROTO_REQUEST, UAV_DAEMON_MSG_REGISTER_WORKLOAD, 0, 1);
  TEST_ASSERT_EQ(TEST_HEADER_SIZE,
                 send(fds[0], header, sizeof(header), MSG_NOSIGNAL));
  TEST_ASSERT_EQ(1, send(fds[0], "x", 1, MSG_NOSIGNAL));
  TEST_ASSERT_EQ(-1,
                 uav_daemon_proto_receive_request(fds[1], &msg, &credentials));
  TEST_ASSERT_EQ(EPROTO, errno);

  close(fds[0]);
  close(fds[1]);
  return 0;
}

TEST(test_daemon_protocol_rejects_oversized_record) {
  const size_t size = TEST_HEADER_SIZE + UAV_PROTO_MAX_PAYLOAD + 1;
  uint8_t* frame;
  struct uav_proto_msg msg;
  struct ucred credentials;
  int fds[2];

  frame = calloc(1, size);
  TEST_ASSERT_NOT_NULL(frame);
  make_header(frame, UAV_DAEMON_PROTO_MAGIC, UAV_DAEMON_PROTO_VERSION,
              UAV_PROTO_REQUEST, UAV_DAEMON_MSG_REGISTER_WORKLOAD, 0,
              UAV_PROTO_MAX_PAYLOAD + 1);

  TEST_ASSERT_EQ(0, socketpair(AF_UNIX, SOCK_SEQPACKET, 0, fds));
  TEST_ASSERT_EQ(0, enable_passcred(fds[1]));
  TEST_ASSERT_EQ(size, send(fds[0], frame, size, MSG_NOSIGNAL));
  TEST_ASSERT_EQ(-1,
                 uav_daemon_proto_receive_request(fds[1], &msg, &credentials));
  TEST_ASSERT_EQ(EMSGSIZE, errno);

  close(fds[0]);
  close(fds[1]);
  free(frame);
  return 0;
}

TEST(test_protocols_reject_each_other) {
  struct uav_proto_msg msg;
  struct ucred credentials;
  int fds[2];

  TEST_ASSERT_EQ(0, socketpair(AF_UNIX, SOCK_SEQPACKET, 0, fds));
  TEST_ASSERT_EQ(0, enable_passcred(fds[1]));
  TEST_ASSERT_EQ(0, uav_proto_seqpacket_send(
                        fds[0], UAV_AGENT_PROTO_MAGIC, UAV_AGENT_PROTO_VERSION,
                        UAV_PROTO_REQUEST, UAV_AGENT_MSG_START, 0, NULL, 0));
  TEST_ASSERT_EQ(-1,
                 uav_daemon_proto_receive_request(fds[1], &msg, &credentials));
  TEST_ASSERT_EQ(EPROTO, errno);

  close(fds[0]);
  close(fds[1]);
  return 0;
}

int main(void) {
  TEST_SUITE("Daemon protocol");

  RUN_TEST(test_daemon_protocol_request_response);
  RUN_TEST(test_daemon_protocol_listener_credentials_are_race_free);
  RUN_TEST(test_daemon_protocol_credentials_follow_sender);
  RUN_TEST(test_daemon_protocol_rejects_wrong_response_type);
  RUN_TEST(test_daemon_protocol_rejects_invalid_frames);
  RUN_TEST(test_daemon_protocol_rejects_oversized_record);
  RUN_TEST(test_protocols_reject_each_other);

  return uav_test_report();
}
