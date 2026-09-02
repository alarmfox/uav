CPPFLAGS       = -Isrc/ -D_XOPEN_SOURCE=500 -D_POSIX_C_SOURCE=200809L -D_GNU_SOURCE
CFLAGS         = -Wall -Wextra -std=c11 -fstack-protector-strong -fPIE
LDFLAGS        = -pie -Wl,-z,relro,-z,now
UAV_LDLIBS     = -larchive
UAVD_LDLIBS    =
AGENT_LDLIBS   = -lcap

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

UAV_TARGET     = uav
UAVD_TARGET    = uav-daemon
AGENT_TARGET   = uav-agent
TEST_TARGETS   = test/test_sandbox.out test/test_transport.out \
                 test/test_agent_protocol.out test/test_daemon_protocol.out
UAV_OBJS       = cli/main.o src/sandbox.o src/container.o src/kvm.o \
                 src/agent_protocol.o src/protocol_utils.o src/transport.o \
                 src/utils.o src/daemon_protocol.o
UAVD_OBJS      = daemon/daemon.o src/daemon_protocol.o src/protocol_utils.o \
                 src/transport.o src/utils.o
AGENT_OBJS     = agent/agent.o src/agent_protocol.o src/transport.o \
                 src/protocol_utils.o src/utils.o
TEST_OBJS      = src/sandbox.o src/container.o src/kvm.o \
                 src/agent_protocol.o src/daemon_protocol.o \
                 src/protocol_utils.o src/transport.o src/utils.o

.PHONY: all test valgrind package-agent run-qemu clean

all: $(UAV_TARGET) $(UAVD_TARGET) $(AGENT_TARGET) $(TEST_TARGETS)

$(UAV_TARGET): $(UAV_OBJS)
	$(CC) $(LDFLAGS) -o $@ $^ $(LDFLAGS) $(UAV_LDLIBS)

$(UAVD_TARGET): $(UAVD_OBJS)
	$(CC) $(LDFLAGS) -o $@ $^ $(LDFLAGS) $(UAVD_LDLIBS)

$(AGENT_TARGET): $(AGENT_OBJS)
	$(CC) $(LDFLAGS) -o $@ $^ $(AGENT_LDLIBS)

$(TEST_TARGETS): %.out: %.o $(TEST_OBJS)
	$(CC) $(LDFLAGS) -o $@ $^ $(LDLIBS) $(UAV_LDLIBS)

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

run-qemu:
	./scripts/run-qemu.sh src/config.h

%.o: %.c
	$(CC) $(CPPFLAGS) $(CFLAGS) -c -o $@ $<

format:
	clang-format -style google -i src/*.c cli/*.c agent/*.c test/*.c src/*.h  test/*.h daemon/*.c
clean:
	$(RM) $(UAV_TARGET) $(AGENT_TARGET) $(TEST_TARGETS) $(UAVD_TARGET) \
		daemon/*.o agent/*.o src/*.o test/*.o cli/*.o
