#include <stdlib.h>
#include <stdio.h>
#include "devzat_mining.h"

#if 0
const uint8_t an_key[32] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32};

void put_key_bin(const uint8_t key[32]) {
	for (int i=0; i<32; i++) {
		putchar(key[i]);
	}
}
#endif

int main(void) {
#if 0
	uint8_t pub[32];
	ed25519_public_key(pub, an_key);
	/*put_key_bin(an_key);*/
	uint8_t test[1000];
	size_t size = openssh_format_pubkey(test, pub);

	cf_sha256_context ctx;
	cf_sha256_init(&ctx);
	cf_sha256_update(&ctx, test, size);
	uint8_t hash[CF_SHA256_HASHSZ];
	cf_sha256_digest_final(&ctx, hash);
	for (int i=0; i<CF_SHA256_HASHSZ; i++) {
		printf("%x", hash[i]);
	}
	printf("\n");
	/*put_key_bin(pub);*/
	/*char* keyfile = openssh_format_key(an_key, pub);*/
	/*printf("%s\n", keyfile);*/
	/*free(keyfile);*/
#endif
	char* keyfile = devzat_mining_multi("cafe", 16);
	printf("%s\n", keyfile);
	free(keyfile);
	return 0;
}

