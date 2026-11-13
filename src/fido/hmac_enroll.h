#ifndef FJ_HMAC_ENROLL_H
#define FJ_HMAC_ENROLL_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "hmac_root.h"

/* Internal enrollment engine. The caller must authenticate the RP hash,
 * guarantee a fresh per-request BOOT press/release, and keep the operation
 * isolated from normal services. Not yet connected to CTAP dispatch. */
typedef struct {
    uint8_t rp_id_hash[32],client_data_hash[32],pin_auth[16];
    bool user_present, has_pin_auth;
    /* Must search all normal profiles, not just the selected profile. */
    bool (*normal_id_exists)(void *ctx,const uint8_t id[16]);
    void *normal_id_ctx;
} fj_hmac_enroll_request_t;
typedef struct {
    uint8_t credential_id[16],public_key[65],auth_data[200];
    size_t auth_data_len;
} fj_hmac_enroll_result_t;
bool fj_hmac_enroll(const fj_hmac_enroll_request_t *request,
                    fj_hmac_root_mode_t mode,const uint8_t otp[32],
                    fj_hmac_enroll_result_t *result);
#endif
