CPPFLAGS       = -Isrc/ -D_XOPEN_SOURCE=500 -D_POSIX_C_SOURCE=200809L -D_GNU_SOURCE
CFLAGS         = -Wall -Wextra -std=c11 -fstack-protector-strong -fPIE
LDFLAGS        = -pie -Wl,-z,relro,-z,now
UAV_LDLIBS     = -larchive
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
AGENT_TARGET   = uav-agent
TEST_TARGETS   = test/test_sandbox.out test/test_transport.out test/test_agent_protocol.out
UAV_OBJS       = uav-cli/main.o src/sandbox.o src/container.o src/kvm.o \
                 src/agent_protocol.o src/transport.o src/utils.o
AGENT_OBJS     = agent/uav-agent.o src/agent_protocol.o src/transport.o \
                 src/utils.o
TEST_OBJS      = src/sandbox.o src/container.o src/kvm.o \
                 src/agent_protocol.o src/transport.o src/utils.o

.PHONY: all test valgrind package-agent clean

all: $(UAV_TARGET) $(AGENT_TARGET) $(TEST_TARGETS)

$(UAV_TARGET): $(UAV_OBJS)
	$(CC) $(LDFLAGS) -o $@ $^ $(LDLIBS) $(UAV_LDLIBS)

$(AGENT_TARGET): $(AGENT_OBJS)
	$(CC) -static $(LDFLAGS) -o $@ $^ $(AGENT_LDLIBS)

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

%.o: %.c
	$(CC) $(CPPFLAGS) $(CFLAGS) -c -o $@ $<

clean:
	$(RM) $(UAV_TARGET) $(AGENT_TARGET) $(TEST_TARGETS) \
		uav-cli/*.o uavd/*.o agent/*.o src/*.o test/*.o
