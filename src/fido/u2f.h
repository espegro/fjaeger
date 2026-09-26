/*
 * Fjaeger - U2F (CTAP1) / CTAP2 authenticator over HID.
 *
 * Implements the U2FHID transport layer and the core U2F operations
 * (REGISTER / AUTHENTICATE) signed with an ECDSA P-256 key, plus the
 * CTAP2 CBOR channel (routed to ctap2.c) for WebAuthn / OpenSSH sk-keys.
 */
#ifndef FJAEGER_U2F_H
#define FJAEGER_U2F_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Initialise the U2F state machine. */
void fj_u2f_init(void);

/* Feed a received 64-byte HID report into the U2F transport. */
void fj_u2f_hid_rx(const uint8_t *report, size_t len);

/* Poll: flush any pending outbound reports over HID. Call from main loop. */
void fj_u2f_task(void);

/* Whether an outbound report is ready to send. */
bool fj_u2f_ready(void);

/* Copy the next pending outbound 64-byte report. Returns true if copied. */
bool fj_u2f_pop_report(uint8_t out[64]);

#ifdef __cplusplus
}
#endif

#endif /* FJAEGER_U2F_H */