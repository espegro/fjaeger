/* CTAP2 hmac-secret cryptographic processing for PIN/UV protocol 1. */
#include "hmac_secret.h"
#include "crypto.h"
#include <string.h>

bool fj_hmac_secret_v1(const uint8_t shared[32], const uint8_t cred_random[32],
                       const uint8_t *salt_enc, size_t salt_len,
                       const uint8_t salt_auth[16], uint8_t *out,
                       size_t out_cap) {
    uint8_t mac[32] = {0}, salt[64] = {0}, result[64] = {0};
    const uint8_t iv[16] = {0};
    bool ok = false;
    if (!shared || !cred_random || !salt_enc || !salt_auth || !out ||
        (salt_len != 32 && salt_len != 64) || out_cap < salt_len)
        goto done;
    if (!fj_hmac_sha256(shared, 32, salt_enc, salt_len, mac) ||
        !fj_ct_equal(mac, salt_auth, 16)) goto done;
    memcpy(salt, salt_enc, salt_len);
    if (!fj_aes_cbc(shared, iv, salt, salt_len, false)) goto done;
    for (size_t i = 0; i < salt_len; i += 32)
        if (!fj_hmac_sha256(cred_random, 32, salt + i, 32, result + i))
            goto done;
    if (!fj_aes_cbc(shared, iv, result, salt_len, true)) goto done;
    memcpy(out, result, salt_len);
    ok = true;
done:
    fj_secure_zero(mac, sizeof(mac));
    fj_secure_zero(salt, sizeof(salt));
    fj_secure_zero(result, sizeof(result));
    return ok;
}
