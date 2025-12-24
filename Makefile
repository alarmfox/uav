BPFTOOL = bpftool

CFLAGS  = -Wall -Wextra -std=c11

ifeq ($(DEBUG), 1)
CFLAGS  += -g -O0
else
CFLAGS  += -O2
endif

LDFLAGS = -lcrypto -lzip -lbpf

# Rules
all: uav

uav: uav.o
	$(CC) $(LDFLAGS) $< -o $@

uav.o: uav.c uav.skel.h
	$(CC) $(CFLAGS) -c $<

uav.skel.h: uav.bpf.o
	$(BPFTOOL) gen skeleton $< name uavbpf > $@

uav.bpf.o: uav.bpf.c vmlinux.h
	clang -Wall -g -O2 -target bpf -c $< -o $@

vmlinux.h:
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $@

clean:
	rm -f vmlinux.h $(APP) uav.skel.h *.o
