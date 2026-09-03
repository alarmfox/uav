#include "agent_protocol.h"

#include <errno.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "protocol_utils.h"

#define UAV_UPLOAD_META_SIZE 12
#define UAV_RUN_HEADER_SIZE 16
#define UAV_RUN_RECORD_SIZE 4

static int uav_agent_proto_expect_empty(int fd,
                                        uint16_t type) {
  struct uav_proto_msg msg;

  if (uav_agent_proto_receive_response(fd, type, &msg) < 0) return -1;
  if (msg.error != 0) {
    errno = msg.error;
    return -1;
  }
  if (msg.length != 0) {
    errno = EPROTO;
    return -1;
  }

  return 0;
}

int uav_agent_proto_send_request(int fd, uint16_t type,
                                 const void* payload, uint32_t length) {
  return uav_proto_stream_send(fd, UAV_AGENT_PROTO_MAGIC,
                               UAV_AGENT_PROTO_VERSION, UAV_PROTO_REQUEST,
                               type, 0, payload, length);
}

int uav_agent_proto_receive_request(int fd, struct uav_proto_msg* msg) {
  return uav_proto_stream_receive(fd, UAV_AGENT_PROTO_MAGIC,
                                  UAV_AGENT_PROTO_VERSION, UAV_PROTO_REQUEST,
                                  msg);
}

int uav_agent_proto_send_response(int fd,
                                  uint16_t request_type, int error,
                                  const void* body, uint32_t body_length) {
  return uav_proto_stream_send(fd, UAV_AGENT_PROTO_MAGIC,
                               UAV_AGENT_PROTO_VERSION, UAV_PROTO_RESPONSE,
                               request_type, error, body, body_length);
}

int uav_agent_proto_receive_response(int fd, uint16_t request_type,
                                     struct uav_proto_msg* msg) {
  if (uav_proto_stream_receive(fd, UAV_AGENT_PROTO_MAGIC,
                               UAV_AGENT_PROTO_VERSION, UAV_PROTO_RESPONSE,
                               msg) < 0)
    return -1;
  if (msg->type != request_type) {
    errno = EPROTO;
    return -1;
  }
  return 0;
}

static int uav_agent_proto_is_loader_variable(const uint8_t* value,
                                              size_t length) {
  const uint8_t* equals;
  size_t name_length;

  equals = memchr(value, '=', length);
  if (equals == NULL) return 0;

  name_length = (size_t)(equals - value);
  return (name_length >= 3 && memcmp(value, "LD_", 3) == 0) ||
         (name_length == strlen("GLIBC_TUNABLES") &&
          memcmp(value, "GLIBC_TUNABLES", name_length) == 0);
}

static int uav_agent_proto_validate_run_params(
    const struct uav_agent_exec_params* params) {
  size_t entries;

  if (params == NULL || params->argv == NULL || params->argc == 0 ||
      params->argc > UINT32_MAX || params->envc > UINT32_MAX ||
      (params->envc > 0 && params->envp == NULL) ||
      (params->flags & ~UAV_AGENT_EXEC_FLAG_MASK) != 0) {
    errno = EINVAL;
    return -1;
  }

  if (params->envc > UAV_AGENT_PROTO_MAX_EXEC_ENTRIES ||
      params->argc > UAV_AGENT_PROTO_MAX_EXEC_ENTRIES - params->envc) {
    errno = E2BIG;
    return -1;
  }

  entries = params->argc + params->envc;
  for (size_t i = 0; i < entries; ++i) {
    const char* value =
        i < params->argc ? params->argv[i] : params->envp[i - params->argc];
    size_t length;

    if (value == NULL) {
      errno = EINVAL;
      return -1;
    }

    length = strlen(value);
    if (length > UINT32_MAX || length > UAV_PROTO_MAX_PAYLOAD) {
      errno = E2BIG;
      return -1;
    }

    if (i >= params->argc) {
      const char* equals = strchr(value, '=');

      if (equals == value || equals == NULL) {
        errno = EINVAL;
        return -1;
      }

      if ((params->flags & UAV_AGENT_EXEC_FLAG_ALLOW_LOADER_ENV) == 0 &&
          uav_agent_proto_is_loader_variable((const uint8_t*)value, length)) {
        errno = EPERM;
        return -1;
      }
    }
  }

  return 0;
}

int uav_agent_proto_encode_run(struct uav_proto_msg* msg,
                               const struct uav_agent_exec_params* params,
                               uint32_t duration_seconds) {
  size_t entries;
  size_t payload_length = UAV_RUN_HEADER_SIZE;
  size_t offset;

  if (msg == NULL) {
    errno = EINVAL;
    return -1;
  }

  if (uav_agent_proto_validate_run_params(params) < 0) return -1;

  entries = params->argc + params->envc;
  for (size_t i = 0; i < entries; ++i) {
    const char* value =
        i < params->argc ? params->argv[i] : params->envp[i - params->argc];
    size_t length = strlen(value);

    if (payload_length > UAV_PROTO_MAX_PAYLOAD - UAV_RUN_RECORD_SIZE ||
        length > UAV_PROTO_MAX_PAYLOAD - payload_length - UAV_RUN_RECORD_SIZE) {
      errno = EMSGSIZE;
      return -1;
    }

    payload_length += UAV_RUN_RECORD_SIZE + length;
  }

  msg->type = UAV_AGENT_MSG_RUN;
  msg->error = 0;
  msg->length = (uint32_t)payload_length;
  uav_proto_put_u32(msg->payload, params->flags);
  uav_proto_put_u32(msg->payload + 4, duration_seconds);
  uav_proto_put_u32(msg->payload + 8, (uint32_t)params->argc);
  uav_proto_put_u32(msg->payload + 12, (uint32_t)params->envc);

  offset = UAV_RUN_HEADER_SIZE;
  for (size_t i = 0; i < entries; ++i) {
    const char* value =
        i < params->argc ? params->argv[i] : params->envp[i - params->argc];
    size_t length = strlen(value);

    uav_proto_put_u32(msg->payload + offset, (uint32_t)length);
    offset += UAV_RUN_RECORD_SIZE;
    memcpy(msg->payload + offset, value, length);
    offset += length;
  }

  return 0;
}

int uav_agent_proto_decode_run(const struct uav_proto_msg* msg,
                               struct uav_agent_exec_request* request) {
  uint32_t flags;
  uint32_t argc;
  uint32_t envc;
  size_t entries;
  size_t offset;
  size_t storage_length = 0;
  size_t pointer_length;
  size_t allocation_length;
  char* storage;
  char** pointers;

  if (msg == NULL || request == NULL) {
    errno = EINVAL;
    return -1;
  }

  memset(request, 0, sizeof(*request));

  if (msg->type != UAV_AGENT_MSG_RUN || msg->length < UAV_RUN_HEADER_SIZE ||
      msg->length > sizeof(msg->payload)) {
    errno = EPROTO;
    return -1;
  }

  flags = uav_proto_get_u32(msg->payload);
  request->duration_seconds = uav_proto_get_u32(msg->payload + 4);
  argc = uav_proto_get_u32(msg->payload + 8);
  envc = uav_proto_get_u32(msg->payload + 12);

  if ((flags & ~UAV_AGENT_EXEC_FLAG_MASK) != 0 || argc == 0 ||
      envc > UAV_AGENT_PROTO_MAX_EXEC_ENTRIES ||
      argc > UAV_AGENT_PROTO_MAX_EXEC_ENTRIES - envc) {
    errno = EPROTO;
    return -1;
  }

  entries = (size_t)argc + (size_t)envc;
  offset = UAV_RUN_HEADER_SIZE;

  for (size_t i = 0; i < entries; ++i) {
    uint32_t length;
    const uint8_t* value;

    if (msg->length - offset < UAV_RUN_RECORD_SIZE) {
      errno = EPROTO;
      return -1;
    }

    length = uav_proto_get_u32(msg->payload + offset);
    offset += UAV_RUN_RECORD_SIZE;
    if ((size_t)length > msg->length - offset ||
        memchr(msg->payload + offset, '\0', length) != NULL) {
      errno = EPROTO;
      return -1;
    }

    value = msg->payload + offset;
    if (i >= argc) {
      const uint8_t* equals = memchr(value, '=', length);

      if (equals == NULL || equals == value) {
        errno = EPROTO;
        return -1;
      }

      if ((flags & UAV_AGENT_EXEC_FLAG_ALLOW_LOADER_ENV) == 0 &&
          uav_agent_proto_is_loader_variable(value, length)) {
        errno = EPERM;
        return -1;
      }
    }

    if (storage_length > SIZE_MAX - (size_t)length - 1) {
      errno = EOVERFLOW;
      return -1;
    }
    storage_length += (size_t)length + 1;
    offset += length;
  }

  if (offset != msg->length) {
    errno = EPROTO;
    return -1;
  }

  /* The entry-count limit makes this multiplication bounded. */
  pointer_length = (entries + 2) * sizeof(char*);
  if (storage_length > SIZE_MAX - pointer_length) {
    errno = EOVERFLOW;
    return -1;
  }
  allocation_length = pointer_length + storage_length;

  request->storage = malloc(allocation_length);
  if (request->storage == NULL) {
    errno = ENOMEM;
    return -1;
  }

  pointers = request->storage;
  request->argv = pointers;
  request->envp = pointers + argc + 1;
  storage = (char*)(request->envp + envc + 1);

  offset = UAV_RUN_HEADER_SIZE;
  for (size_t i = 0; i < entries; ++i) {
    uint32_t length = uav_proto_get_u32(msg->payload + offset);
    const uint8_t* value;

    offset += UAV_RUN_RECORD_SIZE;
    value = msg->payload + offset;
    memcpy(storage, value, length);
    storage[length] = '\0';

    if (i < argc)
      request->argv[i] = storage;
    else
      request->envp[i - argc] = storage;

    storage += (size_t)length + 1;
    offset += length;
  }

  request->argv[argc] = NULL;
  request->envp[envc] = NULL;
  request->flags = flags;
  request->argc = argc;
  request->envc = envc;
  return 0;
}

void uav_agent_proto_free_run(struct uav_agent_exec_request* request) {
  if (request == NULL) return;

  free(request->storage);
  memset(request, 0, sizeof(*request));
}

int uav_agent_proto_upload(int fd, int source_fd,
                           const struct uav_agent_upload_meta* meta) {
  uint8_t begin[UAV_UPLOAD_META_SIZE];
  uint8_t chunk[UAV_AGENT_PROTO_MAX_CHUNK];
  uint32_t remaining;

  if (fd < 0 || source_fd < 0 || meta == NULL || meta->size == 0 ||
      (meta->source_mode & ~0777U) != 0 ||
      (meta->purpose != UAV_AGENT_UPLOAD_DATA &&
       meta->purpose != UAV_AGENT_UPLOAD_EXECUTABLE)) {
    errno = EINVAL;
    return -1;
  }

  uav_proto_put_u32(begin, meta->size);
  uav_proto_put_u32(begin + 4, meta->source_mode);
  uav_proto_put_u32(begin + 8, (uint32_t)meta->purpose);

  if (uav_agent_proto_send_request(fd, UAV_AGENT_MSG_UPLOAD_BEGIN, begin,
                                   sizeof(begin)) < 0)
    return -1;
  if (uav_agent_proto_expect_empty(fd, UAV_AGENT_MSG_UPLOAD_BEGIN) < 0)
    return -1;

  remaining = meta->size;
  while (remaining > 0) {
    size_t wanted = remaining;
    ssize_t count;

    if (wanted > sizeof(chunk)) wanted = sizeof(chunk);

    do {
      count = read(source_fd, chunk, wanted);
    } while (count < 0 && errno == EINTR);

    if (count < 0) return -1;
    if (count == 0) {
      errno = EIO;
      return -1;
    }

    if (uav_agent_proto_send_request(fd, UAV_AGENT_MSG_UPLOAD_CHUNK, chunk,
                                     (uint32_t)count) < 0)
      return -1;
    if (uav_agent_proto_expect_empty(fd, UAV_AGENT_MSG_UPLOAD_CHUNK) < 0)
      return -1;

    remaining -= (uint32_t)count;
  }

  if (uav_agent_proto_send_request(fd, UAV_AGENT_MSG_UPLOAD_END, NULL,
                                   0) < 0)
    return -1;
  return uav_agent_proto_expect_empty(fd, UAV_AGENT_MSG_UPLOAD_END);
}

int uav_agent_proto_decode_upload_begin(const struct uav_proto_msg* msg,
                                        struct uav_agent_upload_meta* meta) {
  uint32_t purpose;

  if (msg == NULL || meta == NULL) {
    errno = EINVAL;
    return -1;
  }

  if (msg->type != UAV_AGENT_MSG_UPLOAD_BEGIN ||
      msg->length != UAV_UPLOAD_META_SIZE) {
    errno = EPROTO;
    return -1;
  }

  meta->size = uav_proto_get_u32(msg->payload);
  meta->source_mode = uav_proto_get_u32(msg->payload + 4);
  purpose = uav_proto_get_u32(msg->payload + 8);

  if (meta->size == 0 || (meta->source_mode & ~0777U) != 0 ||
      (purpose != UAV_AGENT_UPLOAD_DATA &&
       purpose != UAV_AGENT_UPLOAD_EXECUTABLE)) {
    errno = EPROTO;
    return -1;
  }

  meta->purpose = (enum uav_agent_upload_purpose)purpose;
  return 0;
}
