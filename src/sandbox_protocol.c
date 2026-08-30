#include <sys/socket.h>

#include "sandbox_protocol.h"

int uav_sandbox_send_msg(int sockfd, enum uav_sandbox_msg_type type, int data) {
  struct uav_sandbox_msg msg = {
    .type = type,
    .data = data
  };

  ssize_t ret = send(sockfd, &msg, sizeof(msg), MSG_NOSIGNAL);
  return ret == sizeof(msg);
}

int uav_sandbox_recv_msg(int sockfd, struct uav_sandbox_msg *msg) {
  ssize_t ret = recv(sockfd, msg, sizeof(*msg), 0);
  return ret == sizeof(*msg);
}
