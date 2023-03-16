# Flags
CFLAGS += -Wall -Wextra -Wfatal-errors -I./ed25519/ -I./sha2/ -I./utils/ -DCONFIG_MODULE_CRYPTO_CURVE25519_STATIC -lpthread -O3

# Files lists
C_SRC := main.c ed25519/monocypher.c sha2/sha256.c sha2/sha512.c utils/blockwise.c utils/chash.c utils/zero.c utils/base64.c openssh_formatter.c devzat_mining.c
C_HEAD := ed25519/curve25519.h ed25519/monocypher.h sha2/sha2.h utils/bitops.h utils/blockwise.h utils/chash.h utils/handy.h utils/tassert.h utils/zero.h utils/base64.h openssh_formatter.h devzat_mining.h
C_OBJS := $(C_SRC:%.c=%.o)

$(RM) ?= rm -rf
$(CC) ?= gcc

%.o : %.c $(C_HEAD)
	$(CC) -c $< $(CFLAGS) -o $@

mining-devzat-id: $(C_OBJS)
	$(CC) $(C_OBJS) $(CFLAGS) -o $@

clean : 
	$(RM) mining-devzat-id
	$(RM) $(C_OBJS)
