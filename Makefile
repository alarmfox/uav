CPPFLAGS       = -Isrc/ -D_XOPEN_SOURCE=500 -D_POSIX_C_SOURCE=200809L -D_GNU_SOURCE
CFLAGS         = -Wall -Wextra -std=c11 -fstack-protector-strong -fPIE
LDFLAGS        = -pie -Wl,-z,relro,-z,now
LDLIBS         = -larchive

ifeq ($(DEBUG),1)
CFLAGS        += -O0 -g
CPPFLAGS      += -DDEBUG
else
CPPFLAGS      += -D_FORTIFY_SOURCE=2
CFLAGS        += -O2
endif

ifeq ($(RELEASE),1)
CFLAGS        += -Werror
endif

HOST_TARGET    = uav
AGENT_TARGET   = uav-agent
TEST_TARGETS   = test/test_sandbox.out test/test_transport.out
COMMON_OBJS    = src/protocol.o src/transport.o src/utils.o
OBJS           = src/sandbox.o src/container.o src/kvm.o
HOST_OBJS      = src/uav.o
AGENT_OBJS     = agent/uav-agent.o
TEST_OBJS      = test/test_sandbox.o test/test_transport.o

all: $(HOST_TARGET) $(AGENT_TARGET) $(TEST_TARGETS)

$(HOST_TARGET): $(HOST_OBJS) $(OBJS) $(COMMON_OBJS)
	$(CC) $(LDFLAGS) -o $@ $^ $(LDLIBS)

$(AGENT_TARGET): $(AGENT_OBJS) $(COMMON_OBJS)
	$(CC) -static $(LDFLAGS) -o $@ $^

$(TEST_TARGETS): %.out: %.o $(OBJS) $(COMMON_OBJS)
	$(CC) $(LDFLAGS) -o $@ $^ $(LDLIBS)

test: $(TEST_TARGETS)
	@for t in $(TEST_TARGETS); do \
		echo "Running $$t..."; \
		./$$t || exit 1; \
	done

valgrind: $(TEST_TARGETS)
	@for t in $(TEST_TARGETS); do \
		echo "Running $$t with Valgrind..."; \
		valgrind --tool=memcheck \
		--leak-check=full \
		--show-leak-kinds=all \
		--track-origins=yes \
		--error-exitcode=1 \
		--quiet \
		./$$t || exit 1; \
	done

package-agent: $(AGENT_TARGET)
	./scripts/package-agent.sh src/config.h $(AGENT_TARGET)

%.o: %.c
	$(CC) $(CPPFLAGS) $(CFLAGS) -c -o $@ $<

clean:
	$(RM) $(HOST_TARGET) $(HOST_OBJS) $(AGENT_TARGET) $(AGENT_OBJS) $(COMMON_OBJS) $(TEST_TARGETS) $(TEST_OBJS) $(OBJS)
