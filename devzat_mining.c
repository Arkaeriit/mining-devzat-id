#include "openssh_formatter.h"
#include "curve25519.h"
#include <stdbool.h>
#include <threads.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <time.h>
#include "sha2.h"

// Check that a string contains only valid hex numbers
static bool valid_hex(const char* str) {
	for (size_t i=0; i<strlen(str); i++) {
		char c = str[i];
		if (!('0' <= c && c <= '9') && !('a' <= c && c <= 'f') && !('A' <= c && c <= 'F')) {
			return false;
		}
	}
	return true;
}

// Compare an array of bytes to a representation of in in hexadecimal
// {0xca, 0xfe} and "Cafe" would match
// {0x10, 0x12} and "101" would match
// {0x10} and "11" would not match
// It is assume that the string is valid and that the array is long enough
static bool compare_hex_and_array(const uint8_t* array, const char* str) {
	for (size_t i=0; i<strlen(str)/2; i++) { // As /2 rounds down, we only cover full bytes here
		char byte_hex[3] = {0};
		memcpy(byte_hex, str + (2 * i), 2);
		uint8_t hex_convert;
		sscanf(byte_hex, "%hhx", &hex_convert);
		if (array[i] != hex_convert) {
			return false;
		}
	}
	if (strlen(str) % 2) { // If the length of the string is odd, we still have a nibble to check
		char nibble_hex[2] = {str[strlen(str)-1], 0};
		uint8_t hex_convert;
		sscanf(nibble_hex, "%hhx", &hex_convert);
		if (((array[strlen(str)/2] >> 4) & 0x0F) != hex_convert) {
			return false;
		}
	}
	return true;
}

// Compare the few first bytes of the hash of the public key (Devzat's method)
// to the given reference string and see if they match
static bool is_key_hash_matching(const uint8_t* privkey, const char* reference) {
	uint8_t pubkey[CURVE_25519_PUBLIC_KEY_SIZE];
	ed25519_public_key(pubkey, privkey);
	size_t formated_key_size = openssh_format_pubkey(NULL, pubkey);
	uint8_t message[formated_key_size];
	openssh_format_pubkey(message, pubkey);

	cf_sha256_context ctx;
	cf_sha256_init(&ctx);
	cf_sha256_update(&ctx, message, formated_key_size);
	uint8_t hash[CF_SHA256_HASHSZ];
	cf_sha256_digest_final(&ctx, hash);

	return compare_hex_and_array(hash, reference);
}

// Generate a new random private key
static void random_privkey(uint8_t* privkey) {
	for (int i=0; i<CURVE_25519_PRIVATE_KEY_SIZE; i++) {
		privkey[i] = (uint8_t) random(); // A bit inefficient but as this operation is not done a lot, I don't care
	}
}

// Increment a private key
static void increase_privkey(uint8_t* privkey) {
	for (int i=0; i<CURVE_25519_PRIVATE_KEY_SIZE; i++) {
		privkey[i] = privkey[i] + 1;
		if (privkey[i] != 0) {
			break;
		}
	}
}

typedef struct {
	const char* reference;
	bool finished;
	volatile bool stop_force;
	uint8_t working_privkey[CURVE_25519_PRIVATE_KEY_SIZE];
} worker_arguments;

// Generate a random starting private key, use it as a base to generate new
// private keys until one's hash matches with the reference.
// Once it is done, set the finished argument to true.
// If the stop_force argument is set to true, finish even without a result
static void key_mining_worker(worker_arguments* args) {
	uint8_t* privkey = malloc(CURVE_25519_PRIVATE_KEY_SIZE);
	random_privkey(privkey);
	while((!args->stop_force) && (!args->finished)) {
		increase_privkey(privkey);
		if (is_key_hash_matching(privkey, args->reference)) {
			args->finished = true;
			memcpy(args->working_privkey, privkey, CURVE_25519_PRIVATE_KEY_SIZE);
		}
	}
	free(privkey);
}

// Wrapper for key_mining_worker which is of type thrd_start_t
static int key_mining_worker_wrap(void* args) {
	key_mining_worker((worker_arguments*) args);
	return 0;
}

// Generate the content of an openssh key file whose public key matches as a
// Devzat hash the reference.
// The data is malloced
// This is not multi-threaded
char* devzat_mining_mono(const char* reference) {
	if (!valid_hex(reference)) {
		fprintf(stderr, "Error, reference should be a valid hex number.\n");
		return NULL;
	}
	srand(time(NULL));

	worker_arguments args = {
		.reference = reference,
		.finished = false,
		.stop_force = false,
	};
	key_mining_worker(&args);

	uint8_t pubkey[CURVE_25519_PUBLIC_KEY_SIZE];
	ed25519_public_key(pubkey, args.working_privkey);

	return openssh_format_key(args.working_privkey, pubkey);
}

#define ever ;;

// Same as devzat_mining_mono but multithreaded
char* devzat_mining_multi(const char* reference, unsigned int thread_number) {
	if (!valid_hex(reference)) {
		fprintf(stderr, "Error, reference should be a valid hex number.\n");
		return NULL;
	}
	srand(time(NULL));
	char* ret = NULL;

	// Making the threads
	thrd_t threads[thread_number];
	worker_arguments** args_list = malloc(sizeof(worker_arguments*) * thread_number);
	for (unsigned int i=0; i<thread_number; i++) {
		args_list[i] = malloc(sizeof(worker_arguments));
		args_list[i]->reference = reference;
		args_list[i]->finished = false;
		args_list[i]->stop_force = false;

		thrd_create(&threads[i], key_mining_worker_wrap, args_list[i]);
	}

	// Waiting for one thread to finish
	for(ever) {
		for (unsigned int i=0; i<thread_number; i++) {
			if (args_list[i]->finished) {
				uint8_t pubkey[CURVE_25519_PUBLIC_KEY_SIZE];
				ed25519_public_key(pubkey, args_list[i]->working_privkey);
				ret = openssh_format_key(args_list[i]->working_privkey, pubkey);
				goto end_loop;
			}
		}
	}
end_loop:
	// Closing all threads
	for (unsigned int i=0; i<thread_number; i++) {
		args_list[i]->stop_force = true;
		thrd_join(threads[i], NULL);
		free(args_list[i]);
	}
	free(args_list);

	return ret;
}

