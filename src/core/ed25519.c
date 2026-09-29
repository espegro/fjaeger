/* Fjaeger - Ed25519 wrappers backed by Monocypher 4.0.3. */
#include <string.h>

#include "ed25519.h"
#include "crypto.h"
#include "keys.h"
#include "monocypher-ed25519.h"

static void derive_key_pair(const uint8_t seed[FJ_ED25519_SEED_LEN],
                            uint8_t secret_key[64],
                            uint8_t public_key[FJ_ED25519_PUBLIC_LEN]) {
    /* Monocypher intentionally wipes its mutable seed argument. Preserve the
     * persisted seed by deriving from a transient copy. */
    uint8_t seed_copy[FJ_ED25519_SEED_LEN];
    memcpy(seed_copy, seed, sizeof(seed_copy));
    crypto_ed25519_key_pair(secret_key, public_key, seed_copy);
    fj_secure_zero(seed_copy, sizeof(seed_copy));
}

bool fj_ed25519_generate(uint8_t seed[FJ_ED25519_SEED_LEN],
                         uint8_t public_key[FJ_ED25519_PUBLIC_LEN]) {
    if (!seed || !public_key) return false;
    uint8_t secret_key[64];
    fj_random(seed, FJ_ED25519_SEED_LEN);
    derive_key_pair(seed, secret_key, public_key);
    fj_secure_zero(secret_key, sizeof(secret_key));
    return true;
}

bool fj_ed25519_public(const uint8_t seed[FJ_ED25519_SEED_LEN],
                       uint8_t public_key[FJ_ED25519_PUBLIC_LEN]) {
    if (!seed || !public_key) return false;
    uint8_t secret_key[64];
    derive_key_pair(seed, secret_key, public_key);
    fj_secure_zero(secret_key, sizeof(secret_key));
    return true;
}

bool fj_ed25519_sign(const uint8_t seed[FJ_ED25519_SEED_LEN],
                     const uint8_t *message, size_t message_len,
                     uint8_t signature[FJ_ED25519_SIGNATURE_LEN]) {
    if (!seed || (!message && message_len != 0) || !signature) return false;
    uint8_t secret_key[64];
    uint8_t public_key[FJ_ED25519_PUBLIC_LEN];
    derive_key_pair(seed, secret_key, public_key);
    crypto_ed25519_sign(signature, secret_key, message, message_len);
    fj_secure_zero(secret_key, sizeof(secret_key));
    fj_secure_zero(public_key, sizeof(public_key));
    return true;
}
