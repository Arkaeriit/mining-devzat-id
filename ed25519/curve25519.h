#ifndef __CRYPTO_CURVE_25519_H__
#define __CRYPTO_CURVE_25519_H__
#include "monocypher.h"

#define CURVE_25519_PRIVATE_KEY_SIZE 32
#define CURVE_25519_PUBLIC_KEY_SIZE 32
#define CURVE_25519_SIGNATURE_SIZE 64

// X-25519
// -------
static inline void x25519_public_key(uint8_t public_key[32], const uint8_t secret_key[32])
{
	crypto_x25519_public_key(public_key, secret_key);
}
static inline int x25519(uint8_t raw_shared_secret[32], const uint8_t your_secret_key  [32], const uint8_t their_public_key [32])
{
	return crypto_x25519(raw_shared_secret, your_secret_key, their_public_key);
}

// Signatures (EdDSA with curve25519 + sha512)
// --------------------------------------------

// Generate public key
static inline void ed25519_public_key(uint8_t public_key[32], const uint8_t secret_key[32])
{
	crypto_sign_public_key(public_key, secret_key);
}

// Direct interface
static inline void ed25519_sign(uint8_t        signature [64],
				 const uint8_t  secret_key[32],
				 const uint8_t  public_key[32], // optional, may be 0
				 const uint8_t *message, size_t message_size)
{
	crypto_sign(signature, secret_key, public_key, message, message_size);
}

static inline int ed25519_verify(const uint8_t  signature [64],
				 const uint8_t  public_key[32],
				 const uint8_t *message, size_t message_size)
{
	return crypto_check(signature, public_key, message, message_size);
}

#endif /* __CRYPTO_CURVE_25519_H__ */