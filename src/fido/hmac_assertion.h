#ifndef FJ_HMAC_ASSERTION_H
#define FJ_HMAC_ASSERTION_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "hmac_policy.h"
#include "hmac_request.h"
#include "hmac_root.h"

/* Internal assertion engine, not yet connected to CTAP dispatch. The caller
 * must supply actual per-request touch evidence, the selected policy, an
 * expected root protection mode and the authenticated RP hash. It must not
 * reuse presence evidence for a different request. Returns no private key. */
typedef struct {
    uint8_t credential_id[16], rp_id_hash[32], client_data_hash[32];
    fj_hmac_request_t extension;
    bool has_pin_auth, user_present, up_requested, uv_requested;
    uint8_t pin_auth[16];
} fj_hmac_assertion_request_t;
typedef struct {
    uint8_t auth_data[160]; size_t auth_data_len;
    uint8_t signature[80]; size_t signature_len;
} fj_hmac_assertion_result_t;

bool fj_hmac_assertion(const fj_hmac_assertion_request_t *request,
                       const fj_hmac_policy_t *policy,
                       fj_hmac_root_mode_t mode,const uint8_t otp[32],
                       fj_hmac_assertion_result_t *result);
/* CTAP preflight without hmac-secret: PIN/auto/armed policies may sign without
 * presence or PIN, solely to identify this RP-bound credential to systemd.
 * This never exposes ordinary credentials or an hmac-secret output. */
bool fj_hmac_preflight(const uint8_t id[16],const uint8_t rp_hash[32],
                       const uint8_t client_hash[32],const fj_hmac_policy_t *policy,
                       fj_hmac_root_mode_t mode,const uint8_t otp[32],
                       fj_hmac_assertion_result_t *result);
#endif
