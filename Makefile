# Flags
CFLAGS += -Wall -Wextra -Wfatal-errors -I./ed25519/ -I./sha2/ -I./utils/ -DCONFIG_MODULE_CRYPTO_CURVE25519_STACK -O3

# Files lists
C_SRC := main.c ed25519/monocypher.c sha2/sha256.c sha2/sha512.c utils/blockwise.c utils/chash.c utils/zero.c utils/base64.c openssh_formatter.c devzat_mining.c
C_HEAD := ed25519/curve25519.h ed25519/monocypher.h sha2/sha2.h utils/bitops.h utils/blockwise.h utils/chash.h utils/handy.h utils/tassert.h utils/zero.h utils/base64.h openssh_formatter.h devzat_mining.h
C_OBJS := $(C_SRC:%.c=%.o)
COSMO_OBJS := $(C_SRC:%.c=%.cosmo.o)
TARGET := mining-devzat-id

OS := $(shell uname -s)
C11_TREAD := true
ifeq ($(OS),Darwin)
	C11_TREAD := false
endif
ifeq ($(OS),FreeBSD)
	C11_TREAD := false
endif

NO_C11_THREADS_CFLAGS := -I./c11_threads_compatibility -Wno-cast-function-type
NO_C11_THREADS_C_HEAD := c11_threads_compatibility/threads.h

COSMO_CFLAGS += -g -Os -static -fno-pie -no-pie -nostdlib -nostdinc -gdwarf-4  -fno-omit-frame-pointer -pg -mnop-mcount -mno-tls-direct-seg-refs -Wl,--gc-sections -fuse-ld=bfd -Wl,--gc-sections -I./cosmopolitan  -Wl,-T,cosmopolitan/ape.lds $(NO_C11_THREADS_CFLAGS)
COSMO_LDFLAGS += cosmopolitan/cosmopolitan.a cosmopolitan/ape-no-modify-self.o cosmopolitan/crt.o
COSMO_TARGET := mining-devzat-id.com
COSMO_C_HEAD += cosmopolitan/cosmopolitan.h $(NO_C11_THREADS_C_HEAD)

NO_COSMO_LDFLAGS += -lpthread

ifeq ($(C11_TREAD),false)
	CFLAGS += $(NO_C11_THREADS_CFLAGS)
	C_HEAD += $(NO_C11_THREADS_C_HEAD)
endif

RM ?= rm -rf
CC ?= gcc
CP ?= cp -f
OBJCOPY ?= objcopy
DESTDIR ?= /usr/local

all: $(TARGET)

%.o : %.c $(C_HEAD)
	$(CC) -c $< $(CFLAGS) -o $@

%.cosmo.o : %.c $(C_HEAD) $(COSMO_C_HEAD)
	$(CC) -c $< $(CFLAGS) $(COSMO_CFLAGS) -o $@

cosmopolitan/cosmopolitan.h:
	mkdir -p cosmopolitan
	cd cosmopolitan && \
		wget https://justine.lol/cosmopolitan/cosmopolitan-amalgamation-2.2.zip && \
		unzip cosmopolitan-amalgamation-2.2.zip && \
		ln -s cosmopolitan.h stdlib.h && \
		ln -s cosmopolitan.h string.h && \
		ln -s cosmopolitan.h stdio.h && \
		ln -s cosmopolitan.h inttypes.h && \
		ln -s cosmopolitan.h stddef.h && \
		ln -s cosmopolitan.h stdint.h && \
		ln -s cosmopolitan.h stdbool.h && \
		ln -s cosmopolitan.h pthread.h && \
		ln -s cosmopolitan.h unistd.h && \
		ln -s cosmopolitan.h time.h

mining-devzat-id: $(C_OBJS)
	$(CC) $(C_OBJS) $(CFLAGS) $(LDFLAGS) $(NO_COSMO_LDFLAGS) -o $@

mining-devzat-id.com.dbg: $(COSMO_OBJS)
	$(CC) $(COSMO_OBJS) $(CFLAGS) $(COSMO_CFLAGS) $(LDFLAGS) $(COSMO_LDFLAGS) -o $@

mining-devzat-id.com: mining-devzat-id.com.dbg
	$(OBJCOPY) -S -O binary $< $@ 

clean :
	$(RM) mining-devzat-id
	$(RM) $(C_OBJS)
	$(RM) -r cosmopolitan
	$(RM) -r *.com
	$(RM) -r *.com.dbg

install: | mining-devzat-id
	mkdir -p $(DESTDIR)/bin/
	$(CP) mining-devzat-id $(DESTDIR)/bin/mining-devzat-id

uninstall:
	$(RM) $(DESTDIR)/bin/mining-devzat-id

