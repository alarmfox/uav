#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

#include "agent_protocol.h"
#include "uav_test.h"
#include "utils.h"

#define TEST_HEADER_SIZE 16U

static void make_stream_header(uint8_t header[TEST_HEADER_SIZE], uint16_t kind,
                               uint16_t type, uint32_t length) {
  memset(header, 0, TEST_HEADER_SIZE);
  uav_proto_put_u32(header, UAV_AGENT_PROTO_MAGIC);
  uav_proto_put_u16(header + 4, UAV_AGENT_PROTO_VERSION);
  uav_proto_put_u16(header + 6, kind);
  uav_proto_put_u16(header + 8, type);
  uav_proto_put_u32(header + 12, length);
}

static int receive_upload(int fd, const uint8_t* expected, size_t size) {
  struct uav_agent_upload_meta meta;
  struct uav_proto_msg msg;
  size_t offset = 0;

  if (uav_agent_proto_receive_request(fd, &msg) < 0) return 1;
  if (uav_agent_proto_decode_upload_begin(&msg, &meta) < 0) return 1;
  if (meta.size != size || meta.source_mode != 0751 ||
      meta.purpose != UAV_AGENT_UPLOAD_EXECUTABLE)
    return 1;
  if (uav_agent_proto_send_response(fd, UAV_AGENT_MSG_UPLOAD_BEGIN, 0, NULL,
                                    0) < 0)
    return 1;

  while (offset < size) {
    if (uav_agent_proto_receive_request(fd, &msg) < 0) return 1;
    if (msg.type != UAV_AGENT_MSG_UPLOAD_CHUNK || msg.length == 0 ||
        msg.length > UAV_AGENT_PROTO_MAX_CHUNK ||
        msg.length > size - offset ||
        memcmp(msg.payload, expected + offset, msg.length) != 0)
      return 1;
    offset += msg.length;
    if (uav_agent_proto_send_response(fd, UAV_AGENT_MSG_UPLOAD_CHUNK, 0, NULL,
                                      0) < 0)
      return 1;
  }

  if (uav_agent_proto_receive_request(fd, &msg) < 0) return 1;
  if (msg.type != UAV_AGENT_MSG_UPLOAD_END || msg.length != 0) return 1;
  if (uav_agent_proto_send_response(fd, UAV_AGENT_MSG_UPLOAD_END, 0, NULL, 0) <
      0)
    return 1;
  return 0;
}

TEST(test_protocol_request_response) {
  static const uint8_t payload[] = {1, 2, 3, 4};
  struct uav_proto_msg msg;
  int fds[2];

  TEST_ASSERT_EQ(0, socketpair(AF_UNIX, SOCK_STREAM, 0, fds));

  TEST_ASSERT_EQ(0, uav_agent_proto_send_request(
                        fds[0], UAV_AGENT_MSG_START, payload, sizeof(payload)));
  TEST_ASSERT_EQ(0, uav_agent_proto_receive_request(fds[1], &msg));
  TEST_ASSERT_EQ(UAV_AGENT_MSG_START, msg.type);
  TEST_ASSERT_EQ(0, msg.error);
  TEST_ASSERT_EQ(sizeof(payload), msg.length);
  TEST_ASSERT_EQ(0, memcmp(payload, msg.payload, sizeof(payload)));

  TEST_ASSERT_EQ(0, uav_agent_proto_send_response(
                        fds[1], UAV_AGENT_MSG_START, EACCES, payload,
                        sizeof(payload)));
  TEST_ASSERT_EQ(0, uav_agent_proto_receive_response(
                        fds[0], UAV_AGENT_MSG_START, &msg));
  TEST_ASSERT_EQ(EACCES, msg.error);
  TEST_ASSERT_EQ(sizeof(payload), msg.length);
  TEST_ASSERT_EQ(0, memcmp(payload, msg.payload, sizeof(payload)));

  close(fds[0]);
  close(fds[1]);
  return 0;
}

TEST(test_protocol_rejects_wrong_response_type) {
  struct uav_proto_msg msg;
  int fds[2];

  TEST_ASSERT_EQ(0, socketpair(AF_UNIX, SOCK_STREAM, 0, fds));
  TEST_ASSERT_EQ(0, uav_agent_proto_send_response(
                        fds[0], UAV_AGENT_MSG_START, 0, NULL, 0));
  TEST_ASSERT_EQ(-1, uav_agent_proto_receive_response(
                         fds[1], UAV_AGENT_MSG_RUN, &msg));
  TEST_ASSERT_EQ(EPROTO, errno);

  close(fds[0]);
  close(fds[1]);
  return 0;
}

TEST(test_protocol_stream_accepts_split_frame) {
  static const uint8_t payload[] = {1, 2, 3, 4};
  uint8_t header[TEST_HEADER_SIZE];
  struct uav_proto_msg msg;
  int fds[2];

  make_stream_header(header, UAV_PROTO_REQUEST, UAV_AGENT_MSG_START,
                     sizeof(payload));
  TEST_ASSERT_EQ(0, socketpair(AF_UNIX, SOCK_STREAM, 0, fds));
  TEST_ASSERT_EQ(3, write(fds[0], header, 3));
  TEST_ASSERT_EQ(TEST_HEADER_SIZE - 3,
                 write(fds[0], header + 3, TEST_HEADER_SIZE - 3));
  TEST_ASSERT_EQ(2, write(fds[0], payload, 2));
  TEST_ASSERT_EQ(sizeof(payload) - 2,
                 write(fds[0], payload + 2, sizeof(payload) - 2));

  TEST_ASSERT_EQ(0, uav_agent_proto_receive_request(fds[1], &msg));
  TEST_ASSERT_EQ(UAV_AGENT_MSG_START, msg.type);
  TEST_ASSERT_EQ(sizeof(payload), msg.length);
  TEST_ASSERT_EQ(0, memcmp(payload, msg.payload, sizeof(payload)));

  close(fds[0]);
  close(fds[1]);
  return 0;
}

TEST(test_protocol_stream_rejects_partial_header) {
  uint8_t header[TEST_HEADER_SIZE];
  struct uav_proto_msg msg;
  int fds[2];

  make_stream_header(header, UAV_PROTO_REQUEST, UAV_AGENT_MSG_START, 0);
  TEST_ASSERT_EQ(0, socketpair(AF_UNIX, SOCK_STREAM, 0, fds));
  TEST_ASSERT_EQ(TEST_HEADER_SIZE / 2,
                 write(fds[0], header, TEST_HEADER_SIZE / 2));
  close(fds[0]);

  TEST_ASSERT_EQ(-1, uav_agent_proto_receive_request(fds[1], &msg));
  TEST_ASSERT_EQ(ECONNRESET, errno);

  close(fds[1]);
  return 0;
}

TEST(test_protocol_rejects_bad_typed_payload) {
  struct uav_proto_msg msg = {
      .type = UAV_AGENT_MSG_UPLOAD_BEGIN,
      .length = 1,
  };
  struct uav_agent_upload_meta meta;

  TEST_ASSERT_EQ(-1, uav_agent_proto_decode_upload_begin(&msg, &meta));
  TEST_ASSERT_EQ(EPROTO, errno);
  return 0;
}

TEST(test_protocol_run_round_trip) {
  static const char* const expected_argv[] = {"sample", "--flag", "", NULL};
  static const char* const expected_envp[] = {"PATH=/bin", "TERM=xterm", NULL};
  struct uav_agent_exec_params params = {
      .flags = 0,
      .argc = 3,
      .argv = expected_argv,
      .envc = 2,
      .envp = expected_envp,
  };
  struct uav_agent_exec_request decoded;
  struct uav_proto_msg request;
  struct uav_proto_msg received;
  int fds[2];

  TEST_ASSERT_EQ(0, socketpair(AF_UNIX, SOCK_STREAM, 0, fds));
  TEST_ASSERT_EQ(0, uav_agent_proto_encode_run(&request, &params, 7));
  TEST_ASSERT_EQ(0, uav_agent_proto_send_request(
                        fds[0], request.type, request.payload, request.length));
  TEST_ASSERT_EQ(0, uav_agent_proto_receive_request(fds[1], &received));
  TEST_ASSERT_EQ(0, uav_agent_proto_decode_run(&received, &decoded));
  TEST_ASSERT_EQ(7, decoded.duration_seconds);
  TEST_ASSERT_EQ(0, decoded.flags);
  TEST_ASSERT_EQ(3, decoded.argc);
  TEST_ASSERT_EQ(2, decoded.envc);
  TEST_ASSERT_STR_EQ("sample", decoded.argv[0]);
  TEST_ASSERT_STR_EQ("--flag", decoded.argv[1]);
  TEST_ASSERT_STR_EQ("", decoded.argv[2]);
  TEST_ASSERT_STR_EQ("PATH=/bin", decoded.envp[0]);
  TEST_ASSERT_STR_EQ("TERM=xterm", decoded.envp[1]);
  uav_agent_proto_free_run(&decoded);

  TEST_ASSERT_EQ(0, uav_agent_proto_encode_run(&request, &params, 0));
  TEST_ASSERT_EQ(0, uav_agent_proto_decode_run(&request, &decoded));
  TEST_ASSERT_EQ(0, decoded.duration_seconds);
  uav_agent_proto_free_run(&decoded);

  close(fds[0]);
  close(fds[1]);
  return 0;
}

TEST(test_protocol_run_rejects_invalid_payloads) {
  struct uav_proto_msg msg = {
      .type = UAV_AGENT_MSG_RUN,
      .length = 12,
  };
  struct uav_agent_exec_request request;

  uav_proto_put_u32(msg.payload, 0);
  uav_proto_put_u32(msg.payload + 4, 0);
  uav_proto_put_u32(msg.payload + 8, 0);
  TEST_ASSERT_EQ(-1, uav_agent_proto_decode_run(&msg, &request));
  TEST_ASSERT_EQ(EPROTO, errno);

  uav_proto_put_u32(msg.payload + 4, 1);
  uav_proto_put_u32(msg.payload + 8, 1);
  uav_proto_put_u32(msg.payload + 12, 0);
  msg.length = 20;
  uav_proto_put_u32(msg.payload + 16, 5);
  TEST_ASSERT_EQ(-1, uav_agent_proto_decode_run(&msg, &request));
  TEST_ASSERT_EQ(EPROTO, errno);

  msg.length = 21;
  uav_proto_put_u32(msg.payload + 16, 1);
  msg.payload[20] = '\0';
  TEST_ASSERT_EQ(-1, uav_agent_proto_decode_run(&msg, &request));
  TEST_ASSERT_EQ(EPROTO, errno);

  msg.length = 22;
  msg.payload[20] = 'x';
  msg.payload[21] = 'y';
  TEST_ASSERT_EQ(-1, uav_agent_proto_decode_run(&msg, &request));
  TEST_ASSERT_EQ(EPROTO, errno);

  msg.length = UAV_PROTO_MAX_PAYLOAD + 1;
  TEST_ASSERT_EQ(-1, uav_agent_proto_decode_run(&msg, &request));
  TEST_ASSERT_EQ(EPROTO, errno);
  return 0;
}

TEST(test_protocol_run_environment_policy) {
  static const char* const argv[] = {"sample", NULL};
  static const char* const envp[] = {"LD_PRELOAD=sample.so", NULL};
  struct uav_agent_exec_params params = {
      .flags = 0,
      .argc = 1,
      .argv = argv,
      .envc = 1,
      .envp = envp,
  };
  struct uav_agent_exec_request decoded;
  struct uav_proto_msg msg;

  TEST_ASSERT_EQ(-1, uav_agent_proto_encode_run(&msg, &params, 1));
  TEST_ASSERT_EQ(EPERM, errno);

  params.flags = UAV_AGENT_EXEC_FLAG_ALLOW_LOADER_ENV;
  TEST_ASSERT_EQ(0, uav_agent_proto_encode_run(&msg, &params, 1));
  TEST_ASSERT_EQ(0, uav_agent_proto_decode_run(&msg, &decoded));
  TEST_ASSERT_STR_EQ("LD_PRELOAD=sample.so", decoded.envp[0]);
  uav_agent_proto_free_run(&decoded);

  uav_proto_put_u32(msg.payload, 0);
  TEST_ASSERT_EQ(-1, uav_agent_proto_decode_run(&msg, &decoded));
  TEST_ASSERT_EQ(EPERM, errno);
  return 0;
}

TEST(test_protocol_run_sender_validation) {
  static const char* const argv[] = {"sample", NULL};
  struct uav_agent_exec_params params = {
      .flags = 0,
      .argc = 1,
      .argv = argv,
      .envc = 0,
      .envp = NULL,
  };
  struct uav_proto_msg msg;

  params.argv = NULL;
  TEST_ASSERT_EQ(-1, uav_agent_proto_encode_run(&msg, &params, 1));
  TEST_ASSERT_EQ(EINVAL, errno);

  params.argv = argv;
  params.flags = 2;
  TEST_ASSERT_EQ(-1, uav_agent_proto_encode_run(&msg, &params, 1));
  TEST_ASSERT_EQ(EINVAL, errno);

  params.flags = 0;
  params.argc = 0;
  TEST_ASSERT_EQ(-1, uav_agent_proto_encode_run(&msg, &params, 1));
  TEST_ASSERT_EQ(EINVAL, errno);
  return 0;
}

TEST(test_protocol_streamed_upload) {
  uint8_t data[UAV_AGENT_PROTO_MAX_CHUNK + 257];
  struct uav_agent_upload_meta meta = {
      .size = sizeof(data),
      .source_mode = 0751,
      .purpose = UAV_AGENT_UPLOAD_EXECUTABLE,
  };
  FILE* source;
  pid_t child;
  int fds[2];
  int status;

  for (size_t i = 0; i < sizeof(data); ++i) data[i] = (uint8_t)i;

  source = tmpfile();
  TEST_ASSERT_NOT_NULL(source);
  TEST_ASSERT_EQ(0, uav_write_all(fileno(source), data, sizeof(data)));
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
  TEST_ASSERT_MSG(uav_agent_proto_upload(fds[0], fileno(source), &meta) == 0,
                  strerror(errno));
  TEST_ASSERT_EQ(child, waitpid(child, &status, 0));
  TEST_ASSERT(WIFEXITED(status));
  TEST_ASSERT_EQ(0, WEXITSTATUS(status));

  close(fds[0]);
  fclose(source);
  return 0;
}

TEST(test_protocol_upload_stops_on_remote_error) {
  struct uav_agent_upload_meta meta = {
      .size = 1,
      .source_mode = 0751,
      .purpose = UAV_AGENT_UPLOAD_EXECUTABLE,
  };
  struct uav_proto_msg msg;
  FILE* source;
  int fds[2];

  source = tmpfile();
  TEST_ASSERT_NOT_NULL(source);
  TEST_ASSERT(fputc('x', source) != EOF);
  TEST_ASSERT_EQ(0, fflush(source));
  TEST_ASSERT_EQ(0, lseek(fileno(source), 0, SEEK_SET));
  TEST_ASSERT_EQ(0, socketpair(AF_UNIX, SOCK_STREAM, 0, fds));

  TEST_ASSERT_EQ(0, uav_agent_proto_send_response(
                        fds[1], UAV_AGENT_MSG_UPLOAD_BEGIN, EACCES, NULL, 0));
  TEST_ASSERT_EQ(-1, uav_agent_proto_upload(fds[0], fileno(source), &meta));
  TEST_ASSERT_EQ(EACCES, errno);
  TEST_ASSERT_EQ(0, uav_agent_proto_receive_request(fds[1], &msg));
  TEST_ASSERT_EQ(UAV_AGENT_MSG_UPLOAD_BEGIN, msg.type);

  close(fds[0]);
  close(fds[1]);
  fclose(source);
  return 0;
}

int main(void) {
  TEST_SUITE("Agent protocol");

  RUN_TEST(test_protocol_request_response);
  RUN_TEST(test_protocol_rejects_wrong_response_type);
  RUN_TEST(test_protocol_stream_accepts_split_frame);
  RUN_TEST(test_protocol_stream_rejects_partial_header);
  RUN_TEST(test_protocol_rejects_bad_typed_payload);
  RUN_TEST(test_protocol_run_round_trip);
  RUN_TEST(test_protocol_run_rejects_invalid_payloads);
  RUN_TEST(test_protocol_run_environment_policy);
  RUN_TEST(test_protocol_run_sender_validation);
  RUN_TEST(test_protocol_streamed_upload);
  RUN_TEST(test_protocol_upload_stops_on_remote_error);

  return uav_test_report();
}
