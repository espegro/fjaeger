/*
 * Fjaeger - U2F attestation.
 *
 * Generates a self-signed X.509 attestation certificate (and a dedicated
 * attestation key) at startup, and signs the U2F_REGISTER attestation
 * block for newly generated credentials.
 */
#ifndef FJAEGER_ATTESTATION_H
#define FJAEGER_ATTESTATION_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Max size of the DER-encoded attestation certificate. */
#define FJ_ATTEST_CERT_MAX 512

/* Initialise the attestation keypair + self-signed certificate.
 * Called once at startup. Returns true on success. */
bool fj_attest_init(void);

/* Write the DER attestation certificate into out (returns length), or
 * 0 if not initialised. */
size_t fj_attest_cert(uint8_t out[FJ_ATTEST_CERT_MAX]);

/* Sign the U2F_REGISTER attestation block:
 *   reserved(1) || app_id(32) || challenge(32) || key_handle_len(1)
 *   || key_handle || public_key(65)
 * Writes a 64-byte raw ECDSA signature. Returns true on success. */
bool fj_attest_sign(const uint8_t *block, size_t block_len,
                    uint8_t signature[64]);

#ifdef __cplusplus
}
#endif

#endif /* FJAEGER_ATTESTATION_H */