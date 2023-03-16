#ifndef _OPENSSH_FORMATTER_H_
#define _OPENSSH_FORMATTER_H_

#include <stdint.h>

char* openssh_format_key(const uint8_t* privkey, const uint8_t* pubkey);

#endif

