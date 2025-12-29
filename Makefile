CFLAGS  = -Wall -Wextra -D_GNU_SOURCE -D_XOPEN_SOURCE=500 -Isrc/ -std=c11
LDFLAGS = -lbpf -lcrypto -lzip
BPFTOOL = bpftool
EBPF_CFLAGS = -g -O2 -target bpf

ifeq ($(DEBUG),1)
CFLAGS += -O0 -g
else
CFLAGS += -O2
endif

TARGET = uav

# Source files
SRCS = src/uav.c src/sandbox.c src/context.c src/utils.c src/netlink.c src/cgroup.c
OBJS = $(SRCS:.c=.o)
LIB_OBJS = $(filter-out src/uav.o, $(OBJS))

# Tests
TEST_SRCS := $(wildcard test/*.c)
TEST_BINS = $(patsubst test/%.c,test/%,$(TEST_SRCS))

# eBPF compilation
EBPF_SRCS = bpf/sandbox.bpf.c
EBPF_OBJS = $(EBPF_SRCS:.c=.o)
EBPF_SKELETONS = src/sandbox.skel.h

all: $(EBPF_SKELETONS) $(TARGET)

$(TARGET): $(OBJS)
	$(CC) -o $@ $^ $(LDFLAGS)

test/%: test/%.o $(EBPF_SKELETONS) $(LIB_OBJS)
	$(CC) $(CFLAGS) -o $@ $< $(LIB_OBJS) $(LDFLAGS)

.PHONY: test
test: $(TEST_BINS)
	@for t in $(TEST_BINS); do \
		echo "Running $$t..."; \
		./$$t || exit 1; \
	done

valgrind: $(TEST_BINS)
	@for t in $(TEST_BINS); do \
		echo "Running $$t with Valgrind..."; \
		valgrind --tool=memcheck \
		--leak-check=full \
		--show-leak-kinds=all \
		--track-origins=yes \
		--error-exitcode=1 \
		--quiet \
		./$$t || exit 1; \
	done

src/%.skel.h: bpf/%.bpf.o
	$(BPFTOOL) gen skeleton $< > $@

bpf/%.bpf.o: bpf/%.bpf.c bpf/vmlinux.h
	clang $(EBPF_CFLAGS) -c $< -o $@

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

bpf/vmlinux.h:
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $@

clean:
	rm -f $(OBJS) $(TARGET) $(EBPF_OBJ) $(EBPF_SKELETONS) $(TEST_BINS)

.PHONY: all clean
