#ifndef _OPENSSH_FORMATTER_H_
#define _OPENSSH_FORMATTER_H_

#include <stdint.h>
#include <stddef.h>

size_t openssh_format_pubkey(uint8_t* s, const uint8_t* pubkey);
char* openssh_format_key(const uint8_t* privkey, const uint8_t* pubkey);

#endif

