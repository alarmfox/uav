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

$(APP): main.o
	$(CC) $(LDFLAGS) $< -o $@

main.o: main.c av.skel.h
	$(CC) $(CFLAGS) -c $<

vmlinux.h:
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $@

av.bpf.o: av.bpf.c vmlinux.h
	clang -Wall -g -O2 -target bpf -c $< -o $@

av.skel.h: av.bpf.o
	$(BPFTOOL) gen skeleton $< name avbpf > $@

clean:
	rm -f vmlinux.h $(APP) av.skel.h *.o
