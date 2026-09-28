/*
 * Fjaeger - crypto wrappers around mbedTLS.
 *
 * Provides the small set of cryptographic operations the device needs:
 *   - ECDSA P-256 signing (U2F / SSH)
 *   - SHA-256 hashing
 *   - AES-128-XTS block encryption/decryption for the MSC drive
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

/* Generate a valid, non-zero P-256 private scalar. */
bool fj_ecdsa_generate_private(uint8_t private_key[32]);

/* Convert a fixed-width P-256 r||s signature to ASN.1 DER. */
bool fj_ecdsa_signature_der(const uint8_t signature[64], uint8_t *out,
                            size_t out_cap, size_t *out_len);

/* Derive the uncompressed 65-byte P-256 public key
 * (0x04 || X || Y) from a 32-byte private scalar. Returns true on
 * success. */
bool fj_ecdsa_pubkey(const uint8_t private_key[32], uint8_t pub[65]);

/* P-256 ECDH: compute the X coordinate of private_key * peer_pub as the
 * 32-byte shared secret. Used by the CTAP2 PIN/UV auth protocol. */
bool fj_ecdh_shared_secret(const uint8_t private_key[32],
                           const uint8_t peer_pub[65],
                           uint8_t out[32]);

/* AES-256-CBC over 'len' bytes of 'buf' in place, with the given IV.
 * 'len' must be a multiple of 16. Used to transport the PIN and the CTAP2
 * pinToken. */
bool fj_aes_cbc(const uint8_t key[32], const uint8_t iv[16],
                uint8_t *buf, size_t len, bool encrypt);

/* HMAC-SHA256 keyed by 'key' (of 'key_len' bytes) over 'data', written to
 * out[32]. */
bool fj_hmac_sha256(const uint8_t *key, size_t key_len,
                    const uint8_t *data, size_t len,
                    uint8_t out[32]);

/* Constant-time comparison of two buffers of 'n' bytes (FJ-007). Use for all
 * secret / authentication values (PIN verifiers, HMACs, tags, PUK hashes) to
 * avoid timing side channels. Non-secret identifiers (e.g. credential/RP IDs)
 * do not need this. */
bool fj_ct_equal(const void *a, const void *b, size_t n);

/* PBKDF2-HMAC-SHA256 (RFC 2898) with the given salt and iteration count,
 * deriving a 32-byte key. Used for slow, salted password-based key
 * derivation so that a dumped flash store cannot be brute-forced offline
 * with a fast hash. */
bool fj_pbkdf2_sha256(const uint8_t *password, size_t pw_len,
                      const uint8_t *salt, size_t salt_len,
                      uint32_t iterations, uint8_t out[32]);

/* Weak hook called periodically inside the PBKDF2 loop. The firmware (main.c)
 * overrides it to service USB (tud_task) so the host does not deactivate the
 * device during the multi-second derivation. Default (host tests / no USB) is
 * a no-op. */
void fj_pbkdf2_yield(void);

/* Derive 32 bytes of key material from the XTS key
 * and a label, using HKDF-SHA256. Used to derive per-block tweak/sector
 * keys for the MSC. */
bool fj_hkdf(const uint8_t ikm[FJ_AES_KEY_LEN], const char *label,
             const uint8_t *salt, size_t salt_len, uint8_t out[32]);

/* Encrypt/decrypt one 512-byte MSC sector using AES-128-XTS.
 * data_key   : two 128-bit keys
 * tweak      : 16-byte tweak value (sector number based)
 * buf        : 512-byte block, encrypted in place
 * encrypt    : true to encrypt, false to decrypt */
bool fj_xts_sector(const uint8_t data_key[32], const uint8_t tweak[16],
                   uint8_t buf[512], bool encrypt);

/* AES-256-GCM authenticated encryption / decryption of 'in' (len bytes) with
 * the given 32-byte key and 12-byte nonce. The 16-byte authentication tag is
 * read from / written to 'tag'. 'in' and 'out' may alias; 'out' must hold at
 * least 'len' bytes. ciphertext_len equals plaintext_len. Used to wrap the
 * CTAP2 credential private keys and the credential wrapping key (CWK) at
 * rest, so a dumped flash store yields no key material. Returns true on
 * success; decrypt fails (false) if the tag does not authenticate. */
bool fj_aes_gcm_encrypt(const uint8_t key[32], const uint8_t nonce[12],
                        const uint8_t *in, size_t len,
                        uint8_t *out, uint8_t tag[16]);
bool fj_aes_gcm_decrypt(const uint8_t key[32], const uint8_t nonce[12],
                        const uint8_t tag[16],
                        const uint8_t *in, size_t len, uint8_t *out);

/* AES-256-GCM with additional authenticated data (AAD). Use the AAD variants
 * to bind non-encrypted metadata (or a domain/version label) to the
 * ciphertext, so changing it invalidates the authentication tag. */
bool fj_aes_gcm_encrypt_with_aad(const uint8_t key[32], const uint8_t nonce[12],
                                 const uint8_t *aad, size_t aad_len,
                                 const uint8_t *in, size_t len,
                                 uint8_t *out, uint8_t tag[16]);
bool fj_aes_gcm_decrypt_with_aad(const uint8_t key[32], const uint8_t nonce[12],
                                 const uint8_t tag[16],
                                 const uint8_t *aad, size_t aad_len,
                                 const uint8_t *in, size_t len, uint8_t *out);

/* Whether the crypto subsystem initialised correctly. */
bool fj_crypto_ok(void);

#ifdef __cplusplus
}
#endif

#endif /* FJAEGER_CRYPTO_H */
