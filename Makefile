CFLAGS = -Wall -Wextra -D_GNU_SOURCE -D_XOPEN_SOURCE=500 -Isrc/ -std=c11
LDFLAGS = -lbpf -lcrypto -lzip
BPFTOOL = bpftool

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
EBPF_SRC = bpf/uav.bpf.c
EBPF_OBJ = bpf/uav.bpf.o
SKELETON = src/uav.skel.h

all: $(SKELETON) $(TARGET)

$(SKELETON): $(EBPF_OBJ)
	$(BPFTOOL) gen skeleton $< name uavbpf > $@

$(EBPF_OBJ): $(EBPF_SRC) bpf/vmlinux.h
	clang -target bpf -O2 -g -c $< -o $@

$(TARGET): $(OBJS)
	$(CC) -o $@ $^ $(LDFLAGS)

test/%: test/%.o $(SKELETON) $(LIB_OBJS)
	$(CC) $(CFLAGS) -o $@ $< $(LIB_OBJS) $(LDFLAGS)

.PHONY: test
# Run all tests
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

bpf/vmlinux.h:
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $@

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS) $(TARGET) $(EBPF_OBJ) $(SKELETON) $(TEST_BINS)

.PHONY: all clean
