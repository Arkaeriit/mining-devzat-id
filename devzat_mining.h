#ifndef _DEVZAT_MINING_H_
#define _DEVZAT_MINING_H_

#include <stdbool.h>

char* devzat_mining_mono(const char* reference, bool devzat_mode);
char* devzat_mining_multi(const char* reference, unsigned int thread_number, bool devzat_mode);

#endif

