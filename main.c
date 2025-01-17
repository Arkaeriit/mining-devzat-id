#include "devzat_mining.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

static void help(const char* prg_name) {
    printf("mining-devzat-id, a tool to get yourself a shiny SSH ID.\n");
    printf("This tool generates an openSSH ed25519 private key that will make a\n"
           "cool Devzat id or SSH pubkey.\n\n");
    printf("Usage:\n");
    printf("    %s desired-id [-j thread-number] [-o output-file] [-t type]\n", prg_name);
    printf("  desired-id: Vanity part of the resulting id. If desired-id is 000, you\n"
           "              will get an id starting with 000 such as 000c6d33...\n");
    printf("  thread-number: Number of threads used to compute the id.\n"
           "                 Default to 1.\n");
    printf("  output-file: Oath to the file where the generated key will be written.\n"
           "               Default to stdout.\n");
    printf("  type: Either 'devzat-id' to generate a key that will  make the desired\n"
           "        Devzat ID or 'ssh-pubkey' to generate a key with the desired ID\n"
           "        as it's pubkey sufix. Default to Devzat ID.\n");
}

struct args {
    char* desired_id;
    FILE* out;
    int   thread_number;
    bool  devzat_mode;
    bool  asked_for_help;
};

void free_args(struct args* args) {
    if (args) {
        free(args->desired_id);
        if (args->out && args->out != stdout) {
            fclose(args->out);
        }
        free(args);
    }
}

// Read the args and return NULL in case of error
struct args* read_args(int argc, char** argv) {
    struct args* args = calloc(1, sizeof(*args));
    args->thread_number = 1;
    args->out = stdout;
    args->devzat_mode = true;
    int current_arg = 1;
    while (current_arg < argc) {
        if (!strcmp(argv[current_arg], "-h") || !strcmp(argv[current_arg], "help") || !strcmp(argv[current_arg], "-help") || !strcmp(argv[current_arg], "--help")) {
            args->asked_for_help = true;
            return args;
        } else if(!strcmp(argv[current_arg], "-j")) {
            if (++current_arg >= argc) {return NULL;}
            args->thread_number = atoi(argv[current_arg++]);
            if (args->thread_number == 0) {
                return NULL;
            }
        } else if(!strcmp(argv[current_arg], "-o")) {
            if (++current_arg >= argc) {return NULL;}
            args->out = fopen(argv[current_arg++], "w");
            if (!args->out) {
                fprintf(stderr, "Error, unable to open output file.\n");
                return NULL;
            }
        } else if(!strcmp(argv[current_arg], "-t")) {
            if (++current_arg >= argc) {return NULL;}
            if (!strcmp(argv[current_arg], "devzat-id")) {
                args->devzat_mode = true;
            } else if (!strcmp(argv[current_arg], "ssh-pubkey")) {
                args->devzat_mode = false;
            } else {
                return NULL;
            }
            current_arg++;
        } else {
            if (args->desired_id) {
                return NULL;
            } else {
                args->desired_id = strdup(argv[current_arg++]);
            }
        }
    }
    return args;
}

int main(int argc, char** argv) {
    if (argc <= 1) {
        fprintf(stderr, "Error, invalid arguments.\nRun `%s --help` for more info.\n", argv[0]);
        return 1;
    }

    struct args* args = read_args(argc, argv);

    if (!args) {
        fprintf(stderr, "Error, invalid arguments.\nRun `%s --help` for more info.\n", argv[0]);
        return 1;
    }

    if (args->asked_for_help) {
        help(argv[0]);
        return 0;
    }

    char* keyfile;
    if (args->thread_number > 1) {
        keyfile = devzat_mining_multi(args->desired_id, args->thread_number, args->devzat_mode);
    } else {
        keyfile = devzat_mining_mono(args->desired_id, args->devzat_mode);
    }
    if (keyfile == NULL) {
        return 4;
        free_args(args);
    }

    fprintf(args->out, "%s", keyfile);

    free(keyfile);
    free_args(args);

    return 0;
}

