#include "openssh_formatter.h"
#include "curve25519.h"
#include <stdlib.h>
#include <stdio.h>

/*const uint8_t an_key[32] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32};*/
const uint8_t an_key[32] = {0x0e, 0xc5, 0x38, 0xbe, 0xd5, 0x03, 0xac, 0xaa, 0xf8, 0x4f, 0xe3, 0x5f, 0x26, 0x5b, 0x34, 0x27, 0x07, 0x8c, 0xc9, 0x20, 0x79, 0xe3, 0x79, 0x17, 0xb8, 0xa5, 0x04, 0x57, 0xda, 0x28, 0x3d, 0x9f};

void put_key_bin(const uint8_t key[32]) {
	for (int i=0; i<32; i++) {
		putchar(key[i]);
	}
}

int main(void) {
	uint8_t pub[32];
	ed25519_public_key(pub, an_key);
	/*put_key_bin(an_key);*/
	/*put_key_bin(pub);*/
	char* keyfile = openssh_format_key(an_key, pub);
	printf("%s\n", keyfile);
	free(keyfile);
	return 0;
}

