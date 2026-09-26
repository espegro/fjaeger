/*
 * Fjaeger - crypto wrappers around mbedTLS.
 *
 * Provides the small set of cryptographic operations the device needs:
 *   - ECDSA P-256 signing (U2F / SSH)
 *   - SHA-256 hashing
 *   - AES-256-XTS block encryption/decryption for the MSC drive
 *   - HKDF key derivation
 */
#ifndef FJAEGER_CRYPTO_H
#define FJAEGER_CRYPTO_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define FJ_HASH_LEN 32
#define FJ_AES_KEY_LEN 32

/* Compute SHA-256 digest of 'data'. */
void fj_sha256(const uint8_t *data, size_t len, uint8_t out[FJ_HASH_LEN]);

/* Sign 'digest' (32 bytes) with the P-256 private scalar in
 * private_key[32]. Writes a raw 64-byte (r || s) signature. Returns true
 * on success. */
bool fj_ecdsa_sign(const uint8_t private_key[32],
                   const uint8_t digest[FJ_HASH_LEN],
                   uint8_t signature[64]);

/* Derive the uncompressed 65-byte P-256 public key
 * (0x04 || X || Y) from a 32-byte private scalar. Returns true on
 * success. */
bool fj_ecdsa_pubkey(const uint8_t private_key[32], uint8_t pub[65]);

/* Derive 32 bytes of key material for 'slot' from the AES-256 master key
 * and a label, using HKDF-SHA256. Used to derive per-block tweak/sector
 * keys for the MSC. */
bool fj_hkdf(const uint8_t ikm[FJ_AES_KEY_LEN], const char *label,
             const uint8_t *salt, size_t salt_len, uint8_t out[32]);

/* Encrypt/decrypt one 512-byte MSC sector using AES-256-XTS.
 * data_key   : 32-byte data key
 * tweak      : 16-byte tweak value (sector number based)
 * buf        : 512-byte block, encrypted in place
 * encrypt    : true to encrypt, false to decrypt */
bool fj_xts_sector(const uint8_t data_key[32], const uint8_t tweak[16],
                   uint8_t buf[512], bool encrypt);

/* Whether the crypto subsystem initialised correctly. */
bool fj_crypto_ok(void);

#ifdef __cplusplus
}
#endif

#endif /* FJAEGER_CRYPTO_H */