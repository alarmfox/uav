#include <pcap/pcap.h>
#include <poll.h>
#include <pthread.h>
#include <stdlib.h>
#include <sys/eventfd.h>
#include <unistd.h>

#include "sandbox.h"
#include "utils.h"

/* This module only exists to resolve the conflict created by libpcap and libbpf */
struct pcap_thread_args {
  char name[64];
  char ifname[IFNAMSIZ];
  int stop_fd;
};

static void *pcap_capture_loop(void *args_);

int start_capture(struct uav_sandbox *s) {
  struct pcap_thread_args *args = NULL;
  int fd;
  int ret;

  /* Create an eventfd to signal stop */
  fd = eventfd(0, EFD_CLOEXEC);
  if (fd < 0)
    return -1;

  args = malloc(sizeof(*args));
  if (!args) {
    close(fd);
    return -1;
  }

  /* Populate struct */
  safe_strcpy(args->ifname, s->hostifname, IFNAMSIZ);
  args->stop_fd = fd;

  s->capture_stopfd = fd;
  safe_strcpy(args->name, s->id, 64);

  /* Spawn a thread */
  ret = pthread_create(&s->capture_thread, NULL,pcap_capture_loop, args);
  if (ret) {
    close(fd);
    free(args);
    return -1;
  }

  return 0;
}

/* Stop capture */
void stop_capture(struct uav_sandbox *s) {
  uint64_t one = 1;

  if (s->capture_stopfd < 0)
    return;

  write(s->capture_stopfd , &one, sizeof(one));
  pthread_join(s->capture_thread, NULL);

  close(s->capture_stopfd);
  s->capture_stopfd= -1;
}

/* Capture traffic on host side veth */
static void *pcap_capture_loop(void *args_) {
  char errbuf[PCAP_ERRBUF_SIZE];
  char path[PATH_MAX];
  pcap_dumper_t *dumper = NULL;
  pcap_t *handle = NULL;
  struct pcap_thread_args *args = args_;
  int stopfd = args->stop_fd, pcapfd;

  printf("[SANDBOX] starting capturing on %s\n", args->ifname);

  /* Start the capture */
  handle = pcap_open_live(args->ifname, BUFSIZ, 0, 1000, errbuf);
  if (!handle) {
    fprintf(stderr, "pcap_open_live failed: %s\n", errbuf);
    pthread_exit(0);
  }

  snprintf(path, PATH_MAX, "%s.pcap", args->name);

  dumper = pcap_dump_open(handle, path);
  if (!dumper) {
    fprintf(stderr, "pcap_dump_open failed: %s\n", pcap_geterr(handle));
    pthread_exit(0);
  }

  pcapfd = pcap_get_selectable_fd(handle);

  struct pollfd fds[2] = {
    { .fd = pcapfd, .events = POLLIN },
    { .fd = stopfd, .events = POLLIN }
  };

  while (1) {
    int ret = poll(fds, 2, -1);
    if (ret <= 0) continue;

    if (fds[1].revents & POLLIN) break;

    if (fds[0].revents & POLLIN)
      pcap_dispatch(handle, -1, pcap_dump, (u_char *)dumper);
  }

  /* Free resources */
  pcap_dump_close(dumper);
  pcap_close(handle);
  free(args);

  pthread_exit(0);
}
