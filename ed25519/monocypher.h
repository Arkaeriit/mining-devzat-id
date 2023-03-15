// Monocypher version 2.0.6

#ifndef MONOCYPHER_H
#define MONOCYPHER_H

#include <inttypes.h>
#include <stddef.h>

////////////////////////
/// Type definitions ///
////////////////////////

// Do not rely on the size or content on any of those types,
// they may change without notice.

// Signatures (EdDSA)
#include "../sha2/sha2.h"
typedef struct {
    cf_sha512_context hash;
    uint8_t buf[96];
    uint8_t pk [32];
} crypto_sign_ctx;
typedef struct {
    cf_sha512_context hash;
    uint8_t sig[64];
    uint8_t pk [32];
} crypto_check_ctx;

////////////////////////////
/// High level interface ///
////////////////////////////

// Signatures (EdDSA with curve25519 + sha512)
// --------------------------------------------

// Generate public key
void crypto_sign_public_key(uint8_t        public_key[32],
                            const uint8_t  secret_key[32]);

// Direct interface
void crypto_sign(uint8_t        signature [64],
                 const uint8_t  secret_key[32],
                 const uint8_t  public_key[32], // optional, may be 0
                 const uint8_t *message, size_t message_size);
int crypto_check(const uint8_t  signature [64],
                 const uint8_t  public_key[32],
                 const uint8_t *message, size_t message_size);

// Incremental interface for signatures (2 passes)
void crypto_sign_init_first_pass(crypto_sign_ctx *ctx,
                                 const uint8_t  secret_key[32],
                                 const uint8_t  public_key[32]);
void crypto_sign_update(crypto_sign_ctx *ctx,
                        const uint8_t *message, size_t message_size);
void crypto_sign_init_second_pass(crypto_sign_ctx *ctx);
// use crypto_sign_update() again.
void crypto_sign_final(crypto_sign_ctx *ctx, uint8_t signature[64]);

// Incremental interface for verification (1 pass)
void crypto_check_init  (crypto_check_ctx *ctx,
                         const uint8_t signature[64],
                         const uint8_t public_key[32]);
void crypto_check_update(crypto_check_ctx *ctx,
                         const uint8_t *message, size_t message_size);
int crypto_check_final  (crypto_check_ctx *ctx);


////////////////////////////
/// Low level primitives ///
////////////////////////////

// For experts only.  You have been warned.

// X-25519
// -------
void crypto_x25519_public_key(uint8_t       public_key[32],
                              const uint8_t secret_key[32]);
int crypto_x25519(uint8_t       raw_shared_secret[32],
                  const uint8_t your_secret_key  [32],
                  const uint8_t their_public_key [32]);

#endif // MONOCYPHER_H
