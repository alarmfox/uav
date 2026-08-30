#ifndef UAV_SANDBOX_PROTOCOL_H
#define UAV_SANDBOX_PROTOCOL_H

enum uav_sandbox_msg_type {
  MSG_INVALID = 0,
  MSG_CHILD_READY,          /* Child: initial setup done, ready for parent */
  MSG_PARENT_GO,            /* Parent: continue with next phase */
  MSG_PARENT_MAPPINGS_DONE, /* Parent: user mappings configured */
  MSG_CHILD_ERROR,          /* Child: error occurred */
  MSG_PARENT_ERROR,         /* Parent: error occurred */
};

struct uav_sandbox_msg {
  enum uav_sandbox_msg_type type;
  /* Optional data (e.g., error code, fd) */
  int data;
};

int uav_sandbox_send_msg(int sockfd, enum uav_sandbox_msg_type type, int data);
int uav_sandbox_recv_msg(int sockfd, struct uav_sandbox_msg *msg);

#endif //! UAV_SANDBOX_PROTOCOL_H
