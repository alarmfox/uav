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
  struct uav_agent_upload_meta meta;
  uint8_t received[UAV_AGENT_PROTO_MAX_CHUNK + 257];
  FILE* file;
  int ret = 1;

  file = tmpfile();
  if (file == NULL) goto out;

  if (uav_agent_proto_recv(&transport, &msg) < 0) goto close_file;
  if (uav_agent_proto_decode_upload_begin(&msg, &meta) < 0) goto close_file;
  if (meta.size != size || meta.source_mode != 0751 ||
      meta.purpose != UAV_AGENT_UPLOAD_EXECUTABLE)
    goto close_file;

  if (uav_agent_proto_send_response(&transport, UAV_AGENT_MSG_UPLOAD_BEGIN, 0,
                                    NULL, 0) < 0)
    goto close_file;
  if (uav_agent_proto_receive_upload(&transport, fileno(file), meta.size) < 0)
    goto close_file;

  if (lseek(fileno(file), 0, SEEK_SET) < 0) goto close_file;
  if (read(fileno(file), received, sizeof(received)) != (ssize_t)size)
    goto close_file;
  if (memcmp(received, expected, size) != 0) goto close_file;

  if (uav_agent_proto_send_response(&transport, UAV_AGENT_MSG_UPLOAD_END, 0,
                                    NULL, 0) < 0)
    goto close_file;
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
  const uint8_t* body;
  uint32_t body_length;
  int error;
  int value;

  TEST_ASSERT_EQ(0, socketpair(AF_UNIX, SOCK_STREAM, 0, fds));
  first_ctx.fd = fds[0];
  second_ctx.fd = fds[1];

  TEST_ASSERT_MSG(uav_agent_proto_send_response(&first, UAV_AGENT_MSG_RUN,
                                                EACCES, NULL, 0) == 0,
                  strerror(errno));
  TEST_ASSERT_EQ(0, uav_agent_proto_recv(&second, &msg));
  TEST_ASSERT_EQ(0, uav_agent_proto_decode_response(
                        &msg, UAV_AGENT_MSG_RUN, &error, &body, &body_length));
  TEST_ASSERT_EQ(EACCES, error);
  TEST_ASSERT_EQ(0, body_length);

  TEST_ASSERT_EQ(0, uav_agent_proto_send_program_exit(&second, 42));
  TEST_ASSERT_EQ(0, uav_agent_proto_recv(&first, &msg));
  TEST_ASSERT_EQ(0, uav_agent_proto_decode_program_exit(&msg, &value));
  TEST_ASSERT_EQ(42, value);

  close(fds[0]);
  close(fds[1]);
  return 0;
}

TEST(test_protocol_rejects_bad_typed_payload) {
  struct uav_proto_msg msg = {
      .header =
          {
              .kind = UAV_PROTO_REQUEST,
              .type = UAV_AGENT_MSG_UPLOAD_BEGIN,
              .length = 1,
          },
  };
  struct uav_agent_upload_meta meta;

  TEST_ASSERT_EQ(-1, uav_agent_proto_decode_upload_begin(&msg, &meta));
  TEST_ASSERT_EQ(EPROTO, errno);

  msg.header.kind = UAV_PROTO_EVENT;
  msg.header.type = UAV_AGENT_MSG_PROGRAM_EXIT;
  TEST_ASSERT_EQ(-1, uav_agent_proto_decode_program_exit(&msg, &(int){0}));
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
  struct uav_agent_exec_request request;
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

  TEST_ASSERT_EQ(0, uav_agent_proto_send_run(&sender, &params, 7));
  TEST_ASSERT_EQ(0, uav_agent_proto_recv(&receiver, &msg));
  TEST_ASSERT_EQ(0, uav_agent_proto_decode_run(&msg, &request));
  TEST_ASSERT_EQ(7, request.duration_seconds);
  TEST_ASSERT_EQ(0, request.flags);
  TEST_ASSERT_EQ(3, request.argc);
  TEST_ASSERT_EQ(2, request.envc);
  TEST_ASSERT_STR_EQ("sample", request.argv[0]);
  TEST_ASSERT_STR_EQ("--flag", request.argv[1]);
  TEST_ASSERT_STR_EQ("", request.argv[2]);
  TEST_ASSERT_STR_EQ("PATH=/bin", request.envp[0]);
  TEST_ASSERT_STR_EQ("TERM=xterm", request.envp[1]);

  uav_agent_proto_free_run(&request);
  close(fds[0]);
  close(fds[1]);
  return 0;
}

TEST(test_protocol_run_rejects_invalid_payloads) {
  struct uav_proto_msg msg = {
      .header =
          {
              .kind = UAV_PROTO_REQUEST,
              .type = UAV_AGENT_MSG_RUN,
              .length = 12,
          },
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
  msg.header.length = 20;
  uav_proto_put_u32(msg.payload + 16, 5);
  TEST_ASSERT_EQ(-1, uav_agent_proto_decode_run(&msg, &request));
  TEST_ASSERT_EQ(EPROTO, errno);

  msg.header.length = 21;
  uav_proto_put_u32(msg.payload + 16, 1);
  msg.payload[20] = '\0';
  TEST_ASSERT_EQ(-1, uav_agent_proto_decode_run(&msg, &request));
  TEST_ASSERT_EQ(EPROTO, errno);

  msg.header.length = 22;
  msg.payload[20] = 'x';
  msg.payload[21] = 'y';
  TEST_ASSERT_EQ(-1, uav_agent_proto_decode_run(&msg, &request));
  TEST_ASSERT_EQ(EPROTO, errno);

  msg.header.length = UAV_PROTO_MAX_PAYLOAD + 1;
  TEST_ASSERT_EQ(-1, uav_agent_proto_decode_run(&msg, &request));
  TEST_ASSERT_EQ(EPROTO, errno);

  return 0;
}

TEST(test_protocol_run_environment_policy) {
  static const char* const argv[] = {"sample", NULL};
  static const char* const unsafe_envp[] = {"LD_PRELOAD=sample.so", NULL};
  struct uav_agent_exec_params params = {
      .flags = 0,
      .argc = 1,
      .argv = argv,
      .envc = 1,
      .envp = unsafe_envp,
  };
  struct uav_agent_exec_request request;
  struct uav_proto_msg msg = {
      .header =
          {
              .type = UAV_AGENT_MSG_RUN,
          },
  };
  struct test_transport_ctx ctx = {.fd = -1};
  struct uav_transport transport = {
      .ops = &test_transport_ops,
      .ctx = &ctx,
  };
  int fds[2];

  TEST_ASSERT_EQ(-1, uav_agent_proto_send_run(&transport, &params, 1));
  TEST_ASSERT_EQ(EPERM, errno);

  params.flags = UAV_AGENT_EXEC_FLAG_ALLOW_LOADER_ENV;
  TEST_ASSERT_EQ(0, socketpair(AF_UNIX, SOCK_STREAM, 0, fds));
  ctx.fd = fds[0];
  TEST_ASSERT_EQ(0, uav_agent_proto_send_run(&transport, &params, 1));
  {
    struct test_transport_ctx receiver_ctx = {.fd = fds[1]};
    struct uav_transport receiver = {
        .ops = &test_transport_ops,
        .ctx = &receiver_ctx,
    };

    TEST_ASSERT_EQ(0, uav_agent_proto_recv(&receiver, &msg));
  }
  TEST_ASSERT_EQ(0, uav_agent_proto_decode_run(&msg, &request));
  TEST_ASSERT_STR_EQ("LD_PRELOAD=sample.so", request.envp[0]);
  uav_agent_proto_free_run(&request);
  close(fds[0]);
  close(fds[1]);
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
  struct test_transport_ctx ctx = {.fd = -1};
  struct uav_transport transport = {
      .ops = &test_transport_ops,
      .ctx = &ctx,
  };

  params.argv = NULL;
  TEST_ASSERT_EQ(-1, uav_agent_proto_send_run(&transport, &params, 1));
  TEST_ASSERT_EQ(EINVAL, errno);

  params.argv = argv;
  TEST_ASSERT_EQ(-1, uav_agent_proto_send_run(&transport, &params, 0));
  TEST_ASSERT_EQ(EINVAL, errno);

  params.flags = 2;
  TEST_ASSERT_EQ(-1, uav_agent_proto_send_run(&transport, &params, 1));
  TEST_ASSERT_EQ(EINVAL, errno);

  params.flags = 0;
  params.argc = 0;
  TEST_ASSERT_EQ(-1, uav_agent_proto_send_run(&transport, &params, 1));
  TEST_ASSERT_EQ(EINVAL, errno);
  return 0;
}

TEST(test_protocol_streamed_upload) {
  uint8_t data[UAV_AGENT_PROTO_MAX_CHUNK + 257];
  struct test_transport_ctx ctx;
  struct uav_transport transport = {
      .ops = &test_transport_ops,
      .ctx = &ctx,
  };
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
  ctx.fd = fds[0];
  TEST_ASSERT_MSG(
      uav_agent_proto_upload(&transport, fileno(source), &meta) == 0,
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
  RUN_TEST(test_protocol_run_round_trip);
  RUN_TEST(test_protocol_run_rejects_invalid_payloads);
  RUN_TEST(test_protocol_run_environment_policy);
  RUN_TEST(test_protocol_run_sender_validation);
  RUN_TEST(test_protocol_streamed_upload);

  return uav_test_report();
}
