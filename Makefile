CPPFLAGS       = -Isrc/ -D_XOPEN_SOURCE=500 -D_POSIX_C_SOURCE=200809L -D_GNU_SOURCE
CFLAGS         = -Wall -Wextra -std=c11
LDFLAGS        = -larchive

ifeq ($(DEBUG),1)
CFLAGS        += -O0 -g
else
CFLAGS        += -O2
endif

ifeq ($(RELEASE),1)
CFLAGS      += -Werror
endif

TARGET         = uav
SRCS           = src/uav.c src/sandbox.c
OBJS           = src/uav.o src/sandbox.o

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $?

%.o: %.c
	$(CC) $(CPPFLAGS) $(CFLAGS) -c -o $@ $<

clean:
	$(RM) $(TARGET) $(OBJS)
