#include "devzat_mining.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

static void help(const char* prg_name) {
	printf("mining-devzat-id, a tool to get yourself a shiny Devzat ID.\n");
	printf("This tool generates an openSSH ed25519 private key that will make a\n"
	       "cool Devzat id.\n\n");
	printf("Usage:\n");
	printf("    %s desired-id [thread-number [output-file]]\n", prg_name);
	printf("  desired-id: start of the resulting id. If desired-id is 000, you\n"
	       "              will get an id starting with 000 such as 000c6d33...\n");
	printf("  thread-number: number of threads used to compute the id.\n"
	       "                 Default to 1.\n");
	printf("  output-file: path to the file where the generated key will be written.\n"
	       "               Default to stdout.\n");
}

int main(int argc, char** argv) {
	if (argc <= 1) {
		fprintf(stderr, "Error, invalid arguments.\nRun `%s --help` for more info.\n", argv[0]);
		return 1;
	}
	if (!strcmp(argv[1], "-h") || !strcmp(argv[1], "help") || !strcmp(argv[1], "-help") || !strcmp(argv[1], "--help")) {
		help(argv[0]);
		return 0;
	}

	char* keyfile;
	if (argc >= 3) {
		int thread_number = atoi(argv[2]);
		if (thread_number < 1) {
			fprintf(stderr, "Error, thread number should be a strictly positive number.\n");
			return 2;
		}
		keyfile = devzat_mining_multi(argv[1], thread_number, true);
	} else {
		keyfile = devzat_mining_mono(argv[1], true);
	}
	if (keyfile == NULL) {
		return 4;
	}

	FILE* out = stdout;
	if (argc >= 4) {
		out = fopen(argv[3], "w");
		if (out == NULL) {
			fprintf(stderr, "Error, unable to open output file.\n");
			free(keyfile);
			return 8;
		}
	}

	fprintf(out, "%s", keyfile);
	if (out != stdout) {
		fclose(out);
	}
	free(keyfile);

	return 0;
}

