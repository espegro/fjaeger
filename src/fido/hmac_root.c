#include "hmac_root.h"
#include "crypto.h"
#include <string.h>

#define ROOT_VERSION 1u
#define ROOT_AAD_LEN (2u + 16u + 12u)
static void root_aad(const fj_hmac_root_record_t *r, uint8_t aad[ROOT_AAD_LEN]) {
    aad[0] = r->version; aad[1] = r->mode;
    memcpy(aad + 2, r->salt, sizeof(r->salt));
    memcpy(aad + 18, r->nonce, sizeof(r->nonce));
}
static bool valid_mode(fj_hmac_root_mode_t mode) {
    return mode == FJ_HMAC_ROOT_DEVELOPMENT || mode == FJ_HMAC_ROOT_OTP;
}
bool fj_hmac_root_create(fj_hmac_root_record_t *out,
                         fj_hmac_root_mode_t mode, const uint8_t root[32],
                         const uint8_t otp[32], const uint8_t salt[16],
                         const uint8_t nonce[12]) {
    if (!out || !root || !salt || !nonce || !valid_mode(mode) ||
        (mode == FJ_HMAC_ROOT_OTP && !otp)) return false;
    fj_hmac_root_record_t r = {0};
    uint8_t key[32] = {0}, aad[ROOT_AAD_LEN] = {0};
    r.version = ROOT_VERSION; r.mode = (uint8_t)mode;
    memcpy(r.salt, salt, sizeof(r.salt)); memcpy(r.nonce, nonce, sizeof(r.nonce));
    bool ok = true;
    if (mode == FJ_HMAC_ROOT_DEVELOPMENT) {
        memcpy(r.wrapped_root, root, sizeof(r.wrapped_root));
    } else {
        root_aad(&r, aad);
        ok = fj_hkdf(otp, "Fjaeger hmac root OTP v1", r.salt, sizeof(r.salt), key) &&
             fj_aes_gcm_encrypt_with_aad(key, r.nonce, aad, sizeof(aad), root, 32,
                                         r.wrapped_root, r.tag);
    }
    if (ok) *out = r;
    fj_secure_zero(key, sizeof(key)); fj_secure_zero(aad, sizeof(aad));
    fj_secure_zero(&r, sizeof(r));
    return ok;
}
bool fj_hmac_root_open(const fj_hmac_root_record_t *r,
                       fj_hmac_root_mode_t expected_mode,
                       const uint8_t otp[32], uint8_t root[32]) {
    if (!root) return false;
    if (!r || !valid_mode(expected_mode) || r->version != ROOT_VERSION ||
        r->mode != (uint8_t)expected_mode ||
        (expected_mode == FJ_HMAC_ROOT_OTP && !otp)) {
        fj_secure_zero(root, 32); return false;
    }
    uint8_t key[32] = {0}, aad[ROOT_AAD_LEN] = {0};
    bool ok = true;
    if (expected_mode == FJ_HMAC_ROOT_DEVELOPMENT) {
        memcpy(root, r->wrapped_root, 32);
    } else {
        root_aad(r, aad);
        ok = fj_hkdf(otp, "Fjaeger hmac root OTP v1", r->salt, sizeof(r->salt), key) &&
             fj_aes_gcm_decrypt_with_aad(key, r->nonce, r->tag, aad, sizeof(aad),
                                         r->wrapped_root, 32, root);
    }
    if (!ok) fj_secure_zero(root, 32);
    fj_secure_zero(key, sizeof(key)); fj_secure_zero(aad, sizeof(aad));
    return ok;
}
