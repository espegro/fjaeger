#ifndef FJ_HMAC_CTAP_H
#define FJ_HMAC_CTAP_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "hmac_policy.h"
#include "hmac_root.h"

/* Internal CTAP adapter. Caller must classify and route only requests with
 * hmac-secret, supply a verified per-request press, retain the policy across
 * calls and select root mode explicitly. Not registered in normal dispatch. */
typedef struct {
    const fj_hmac_policy_t *policy;
    fj_hmac_root_mode_t mode;
    const uint8_t *otp;
    bool user_present;
    /* Required for enrollment; must search all ordinary credential profiles. */
    bool (*normal_id_exists)(void *ctx,const uint8_t id[16]);
    void *normal_id_ctx;
} fj_hmac_ctap_context_t;
typedef enum { FJ_HMAC_ROUTE_NORMAL, FJ_HMAC_ROUTE_HMAC, FJ_HMAC_ROUTE_INVALID } fj_hmac_route_t;
/* Classify makeCredential/getAssertion without changing state. A malformed or
 * duplicate extension must not silently fall through to normal dispatch. */
fj_hmac_route_t fj_hmac_ctap_classify(const uint8_t *msg,size_t len);
/* msg contains CTAP command byte followed by CBOR. Returns a CTAP status byte
 * and optionally a CBOR response; unsupported requests return an error. */
size_t fj_hmac_ctap_dispatch(const uint8_t *msg,size_t len,
                             const fj_hmac_ctap_context_t *ctx,
                             uint8_t *out,size_t capacity);
/* Handles only an up=false preflight targeting a separate credential. Returns
 * false when the normal dispatcher should handle the request. */
bool fj_hmac_ctap_preflight(const uint8_t *msg,size_t len,
                            const fj_hmac_ctap_context_t *ctx,
                            uint8_t *out,size_t capacity,size_t *written);
#endif
