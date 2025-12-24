APP     = uav
BPFTOOL = bpftool

# CC      = gcc
CFLAGS  = -Wall -Wextra -std=c11

ifeq ($(DEBUG), 1)
CFLAGS  += -g -O0
else
CFLAGS  += -O2
endif

LDFLAGS = -lcrypto -lzip -lbpf

# Rules
all: $(APP)

$(APP): uav.o
	$(CC) $(LDFLAGS) $< -o $@

uuav.o: uuav.c uav.skel.h
	$(CC) $(CFLAGS) -c $<

vmlinux.h:
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $@

uav.bpf.o: uav.bpf.c vmlinux.h
	clang -Wall -g -O2 -target bpf -c $< -o $@

uav.skel.h: uav.bpf.o
	$(BPFTOOL) gen skeleton $< name uavbpf > $@

clean:
	rm -f vmlinux.h $(APP) uav.skel.h *.o
