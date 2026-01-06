#ifndef __UAV_MONITOR_H
#define __UAV_MONITOR_H

#include "monitor.skel.h"

struct uav_monitor {
  /* Reference to eBPF program */
  struct monitor_bpf *prog;
};

int uav_monitor_init(struct uav_monitor *m);
int uav_monitor_start(const struct uav_monitor *m);
void uav_monitor_destroy(struct uav_monitor *m);

#endif // !__UAV_MONITOR_H
