/*
 * Fjaeger - CTAP2 (FIDO2) authenticator operations.
 *
 * Implements the CTAP2 CBOR commands needed for WebAuthn and OpenSSH
 * sk-ecdsa security keys:
 *   - authenticatorGetInfo       (0x04)
 *   - authenticatorMakeCredential(0x01) with attestation format "none"
 *   - authenticatorGetAssertion  (0x02)
 *
 * Attestation uses the "none" format: no X.509 certificate chain is
 * emitted, matching what OpenSSH and most WebAuthn relying parties accept.
 * The credential signing key is a fresh ECDSA P-256 (ES256) keypair.
 */
#ifndef FJAEGER_CTAP2_H
#define FJAEGER_CTAP2_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Initialise the CTAP2 credential store. */
void fj_ctap2_init(void);

/* Poll: flush deferred flash writes. Call from the main loop. */
void fj_ctap2_task(void);

/* Forget the in-RAM credential cache. Persistence is cleared by the caller's
 * factory-reset transaction. */
void fj_ctap2_forget_all(void);

/* Drop every live credential bound to the given profile so that a deferred
 * flash flush can never write back credentials that were erased. Call this
 * when a profile is erased to keep the live cache consistent with the
 * persistent store. */
void fj_ctap2_forget_profile(unsigned profile_id);

/* Delete the single credential with the given id from the given profile's
 * credential set (active-profile scoped). Returns true if one was removed;
 * the change is persisted on the next fj_ctap2_task(). */
bool fj_ctap2_delete_cred(unsigned profile_id, const uint8_t *credential_id);

/* Invalidate any in-progress resident-credential discovery. Call after the
 * active profile changes so a buffered credential selection is not reused
 * across a profile switch. */
void fj_ctap2_invalidate_discovery(void);

/* Process one complete CTAP2 message. 'msg' is the CBOR-message payload
 * as received on the U2FHID CBOR channel (first byte is the CTAP2 command
 * byte). Writes the CBOR response into 'out' (up to out_cap bytes) and
 * returns its length. Always returns > 0; on failure a CTAP2 error code
 * (encoded as a CBOR integer) is produced. */
size_t fj_ctap2_dispatch(const uint8_t *msg, size_t len,
                         uint8_t *out, size_t out_cap);

#ifdef __cplusplus
}
#endif

#endif /* FJAEGER_CTAP2_H */
