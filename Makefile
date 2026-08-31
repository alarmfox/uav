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
TEST_TARGETS   = test/test_sandbox.out
COMMON_OBJS    = src/sandbox_protocol.o
OBJS           = src/utils.o src/sandbox.o src/sandbox_ns.o src/sandbox_kvm.o
HOST_OBJS      = src/uav.o
AGENT_OBJS     = agent/uav-agent.o
TEST_OBJS      = test/test_sandbox.o

all: $(HOST_TARGET) $(AGENT_TARGET) $(TEST_TARGETS)

$(HOST_TARGET): $(HOST_OBJS) $(OBJS) $(COMMON_OBJS)
	$(CC) $(LDFLAGS) -o $@ $^ $(LDLIBS)

$(AGENT_TARGET): $(AGENT_OBJS) $(COMMON_OBJS)
	$(CC) $(LDFLAGS) -o $@ $^

$(TEST_TARGETS): %.out: %.o $(OBJS) $(COMMON_OBJS)
	$(CC) $(LDFLAGS) -o $@ $^ $(LDLIBS)

%.o: %.c
	$(CC) $(CPPFLAGS) $(CFLAGS) -c -o $@ $<

clean:
	$(RM) $(HOST_TARGET) $(HOST_OBJS) $(AGENT_TARGET) $(AGENT_OBJS) $(COMMON_OBJS) $(TEST_TARGETS) $(TEST_OBJS) $(OBJS)
