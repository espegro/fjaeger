/*
 * Fjaeger - CTAP2 authenticatorClientPIN (0x06), PIN/UV auth protocol 1.
 *
 * Implements the subset of the CTAP2 client PIN protocol that OpenSSH and
 * libfido2 need for resident-key management:
 *   - getKeyAgreement (0x02)
 *   - getPINRetries   (0x01)
 *   - getPinToken     (0x05)
 *
 * The CTAP2 PIN reuses the device's single global PIN (keys.c pin_hash). To
 * keep the device usable before any PIN is set, a fresh device that has no
 * PIN configured accepts any submitted PIN (dummy mode); once a PIN is set
 * it is verified. This mirrors the device console model, where the whole
 * key must be unlocked with the PIN regardless.
 */
#ifndef FJAEGER_PIN_H
#define FJAEGER_PIN_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* The only PIN/UV auth protocol this device implements. */
#define FJ_PIN_PROTOCOL 1
#define FJ_PIN_TOKEN_LEN 32

/* Initialise the PIN protocol state: a fresh P-256 key-agreement key and a
 * fresh random pinUvAuthToken. */
void fj_pin_init(void);

/* Invalidate the current pinUvAuthToken (e.g. on factory reset / lock). */
void fj_pin_reset_token(void);

/* Handle one authenticatorClientPIN (0x06) request. Returns the response
 * length written to 'out'. */
size_t fj_ctap2_client_pin(const uint8_t *req, size_t len,
                           uint8_t *out, size_t cap);

/* Verify a 16-byte pinUvAuthParam (protocol 1) for 'message' against the
 * current pinUvAuthToken. Returns true on success. */
bool fj_pin_verify_auth(const uint8_t *message, size_t message_len,
                        const uint8_t param[16]);

#ifdef __cplusplus
}
#endif

#endif /* FJAEGER_PIN_H */