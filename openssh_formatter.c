/*
 * This file contains functions to format ed25519 keys into the openssh format.
 * The openssh key will not be encrypted.
 */

#include "openssh_formatter.h"
#include "base64.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#define AUTH_MAGIC          "openssh-key-v1\0"
#define AUTH_MAGIC_SIZE     (strlen(AUTH_MAGIC) + 1)
#define NUMBER_OF_KEYS      "\x01"
#define NUMBER_OF_KEYS_SIZE 1
#define NONE                "none"
#define KEY_TYPE            "ssh-ed25519"
#define COMMENT             "Made with mining-devzat-key © Arkaeriit"
#define ED25519_SIZE        32
#define HEADER_MARK         "-----BEGIN OPENSSH PRIVATE KEY-----"
#define FOOTER_MARK         "-----END OPENSSH PRIVATE KEY-----"

// Write the number into the given string and return the number of byte
// written.
// If the string is NULL, no writting is done but the number of bytes that
// could have been written is returned. That behavior will be the same on
// all other static functions of this file.
static size_t write_le_number(uint8_t* s, uint32_t n) {
	for (size_t i=0; i<sizeof(uint32_t); i++) {
		uint32_t shifted = n >> (8 * (3 - i));
		if (s != NULL) {
			s[i] = (char) (shifted & 0xFF);
		}
	}
	return sizeof(uint32_t);
}

// Write the data to the string
static size_t write_data(uint8_t* s, size_t size, const uint8_t* data) {
	for (size_t i=0; i<size; i++) {
		if (s != NULL) {
			s[i] = data[i];
		}
	}
	return size;
}

// Write the length of the data, and then the data.
static size_t write_size_data(uint8_t* s, size_t size, const uint8_t* data) {
	size_t size_number = write_le_number(s, size);
	size_t size_data = write_data(s == NULL ? NULL : s + size_number, size, data);
	return size_number + size_data;
}

// Write a length of a string and then its content
static size_t write_string(uint8_t* s, const char* data) {
	return write_size_data(s, strlen(data), (const uint8_t*) data);
}

// Write the SSH key header
static size_t write_header(uint8_t* s) {
	size_t ret = write_data(s, AUTH_MAGIC_SIZE, (const uint8_t*) AUTH_MAGIC);
	ret += write_string(s == NULL ? s : s + ret, NONE);
	ret += write_string(s == NULL ? s : s + ret, NONE);
	ret += write_string(s == NULL ? s : s + ret, "");
	ret += write_le_number(s == NULL ? s : s + ret, NUMBER_OF_KEYS_SIZE);
	return ret;
}

// Write the public key content
static size_t write_public_key_data(uint8_t* s, const uint8_t* pubkey) {
	size_t ret = write_string(s, KEY_TYPE);
	ret += write_size_data(s == NULL ? s : s + ret, ED25519_SIZE, pubkey);
	return ret;
}

// Write the public key block
static size_t write_pubkey_block(uint8_t* s, const uint8_t* pubkey) {
	size_t data_size = write_public_key_data(NULL, pubkey);
	size_t ret = write_le_number(s, (uint32_t) data_size);
	ret += write_public_key_data(s == NULL ? s : s + ret, pubkey);
	return ret;
}

// Write the private key content
static size_t write_private_key_data(uint8_t* s, const uint8_t* privkey, const uint8_t* pubkey) {
	uint8_t concat_keys[ED25519_SIZE * 2];
	memcpy(concat_keys, privkey, ED25519_SIZE);
	memcpy(concat_keys + ED25519_SIZE, pubkey, ED25519_SIZE);
	return write_size_data(s, ED25519_SIZE * 2, concat_keys);
}

// Write the private key block
static size_t write_privkey_block(uint8_t* s, const uint8_t* privkey, const uint8_t* pubkey) {
	size_t privkey_no_size(uint8_t* s, const uint8_t* privkey, const uint8_t* pubkey) {
		/*size_t ret = write_data(s, sizeof(uint64_t), (const uint8_t*) KEY_TYPE); // Dummy 64 bit value. Could be a checksum but is not needed*/
		const uint8_t sum[] = {0x7e, 0xd0, 0x47, 0x27, 0x7e, 0xd0, 0x47, 0x27};
		size_t ret = write_data(s, sizeof(uint64_t), sum); // Dummy 64 bit value. Could be a checksum but is not needed
		ret += write_public_key_data(s == NULL ? s : s + ret, pubkey);
		ret += write_private_key_data(s == NULL ? s : s + ret, privkey, pubkey);
		ret += write_string(s == NULL ? s : s + ret, COMMENT);
		// Padding to 8 bytes
		uint8_t padding_value = 1;
		while ((ret) % 8 != 0) {
			ret += write_data(s == NULL ? s : s + ret, 1, &padding_value);
			padding_value++;
		}
		return ret;
	}

	size_t data_size = privkey_no_size(NULL, privkey, pubkey);
	size_t ret = write_le_number(s, (uint32_t) data_size);
	ret += privkey_no_size(s == NULL ? s : s + ret, privkey, pubkey);
	return ret;
}

// Write a whole openssh key in binary
static size_t write_openssh(uint8_t* s, const uint8_t* privkey, const uint8_t* pubkey) {
	size_t ret = write_header(s);
	ret += write_pubkey_block(s == NULL ? s : s + ret, pubkey);
	ret += write_privkey_block(s == NULL ? s : s + ret, privkey, pubkey);
	return ret;
}

// Return a malloced string with the content of an openSSH key file
// for the given ed25519 keys
char* openssh_format_key(const uint8_t* privkey, const uint8_t* pubkey) {
	size_t bin_size = write_openssh(NULL, privkey, pubkey);
	uint8_t bin_data[bin_size];
	write_openssh(bin_data, privkey, pubkey);
#if 0
	for (size_t i=0; i<bin_size; i++) {
		putchar(bin_data[i]);
	}
#endif
	char* base64_data = base64_encode(bin_data, bin_size);
	char* ret = malloc(strlen(HEADER_MARK) + strlen(FOOTER_MARK) + strlen(base64_data) + 4);
	strcpy(ret, HEADER_MARK);
	strcat(ret, "\n");
	strcat(ret, base64_data);
	strcat(ret, "\n");
	strcat(ret, FOOTER_MARK);
	strcat(ret, "\n");

	free(base64_data);
	return ret;
}

