# Flags
CFLAGS += -Wall -Wextra -Wfatal-errors -I./ed25519/ -I./sha2/ -I./utils/ -DCONFIG_MODULE_CRYPTO_CURVE25519_STACK -O3
LDFLAGS += -lpthread

# Files lists
C_SRC := main.c ed25519/monocypher.c sha2/sha256.c sha2/sha512.c utils/blockwise.c utils/chash.c utils/zero.c utils/base64.c openssh_formatter.c devzat_mining.c
C_HEAD := ed25519/curve25519.h ed25519/monocypher.h sha2/sha2.h utils/bitops.h utils/blockwise.h utils/chash.h utils/handy.h utils/tassert.h utils/zero.h utils/base64.h openssh_formatter.h devzat_mining.h
C_OBJS := $(C_SRC:%.c=%.o)

ifeq ($(OS),Darwin)
	CFLAGS += -I./c11_threads_compatibility -Wno-cast-function-type
	C_HEAD += c11_threads_compatibility/threads.h
endif

RM ?= rm -rf
CC ?= gcc
CP ?= cp -f
DESTDIR ?= /usr/local

%.o : %.c $(C_HEAD)
	$(CC) -c $< $(CFLAGS) -o $@

mining-devzat-id: $(C_OBJS)
	$(CC) $(C_OBJS) $(CFLAGS) $(LDFLAGS) -o $@

clean :
	$(RM) mining-devzat-id
	$(RM) $(C_OBJS)

install: | mining-devzat-id
	mkdir -p $(DESTDIR)/bin/
	$(CP) mining-devzat-id $(DESTDIR)/bin/mining-devzat-id

uninstall:
	$(RM) $(DESTDIR)/bin/mining-devzat-id

