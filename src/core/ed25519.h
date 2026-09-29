/* Fjaeger - Ed25519 wrappers backed by pinned Monocypher. */
#ifndef FJAEGER_ED25519_H
#define FJAEGER_ED25519_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define FJ_ED25519_SEED_LEN 32
#define FJ_ED25519_PUBLIC_LEN 32
#define FJ_ED25519_SIGNATURE_LEN 64

/* Generate a random seed and its RFC 8032 Ed25519 public key. The seed is the
 * only private material that needs to be persisted. */
bool fj_ed25519_generate(uint8_t seed[FJ_ED25519_SEED_LEN],
                         uint8_t public_key[FJ_ED25519_PUBLIC_LEN]);

/* Derive the public key from a persisted 32-byte seed. */
bool fj_ed25519_public(const uint8_t seed[FJ_ED25519_SEED_LEN],
                       uint8_t public_key[FJ_ED25519_PUBLIC_LEN]);

/* Sign the complete message with pure Ed25519 (not Ed25519ph). */
bool fj_ed25519_sign(const uint8_t seed[FJ_ED25519_SEED_LEN],
                     const uint8_t *message, size_t message_len,
                     uint8_t signature[FJ_ED25519_SIGNATURE_LEN]);

#ifdef __cplusplus
}
#endif

#endif /* FJAEGER_ED25519_H */
