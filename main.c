#include "curve25519.h"
#include <stdio.h>

const uint8_t an_key[32] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32};

static void put_key_bin(const uint8_t key[32]) {
	for (int i=0; i<32; i++) {
		putchar(key[i]);
	}
}

int main(void) {
	uint8_t pub[32];
	ed25519_public_key(pub, an_key);
	put_key_bin(an_key);
	/*put_key_bin(pub);*/
	return 0;
}

