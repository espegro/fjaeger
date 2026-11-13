#include "hmac_credential.h"
#include "crypto.h"
#include <string.h>

#define HMAC_AAD_LENGTH (1u + 16u + 32u + 65u)
static size_t credential_aad(const fj_hmac_credential_t *r, uint8_t *aad) {
    size_t n = 0;
    aad[n++] = 1;
    memcpy(aad + n, r->credential_id, sizeof(r->credential_id)); n += sizeof(r->credential_id);
    memcpy(aad + n, r->rp_id_hash, sizeof(r->rp_id_hash)); n += sizeof(r->rp_id_hash);
    memcpy(aad + n, r->public_key, sizeof(r->public_key)); n += sizeof(r->public_key);
    return n;
}

bool fj_hmac_credential_seal(fj_hmac_credential_t *record,
                             const uint8_t root[32],
                             const uint8_t material[FJ_HMAC_MATERIAL_LEN]) {
    if (!record || !root || !material) return false;
    uint8_t key[32] = {0}, aad[HMAC_AAD_LENGTH] = {0};
    uint8_t ciphertext[FJ_HMAC_MATERIAL_LEN] = {0}, tag[16] = {0};
    size_t n = credential_aad(record, aad);
    bool ok = fj_hkdf(root, "Fjaeger hmac credential v1", record->credential_id,
                      sizeof(record->credential_id), key) &&
              fj_aes_gcm_encrypt_with_aad(key, record->nonce, aad, n, material,
                                           FJ_HMAC_MATERIAL_LEN, ciphertext, tag);
    if (ok) {
        memcpy(record->ciphertext, ciphertext, sizeof(ciphertext));
        memcpy(record->tag, tag, sizeof(tag));
    }
    fj_secure_zero(key, sizeof(key));
    fj_secure_zero(aad, sizeof(aad));
    fj_secure_zero(ciphertext, sizeof(ciphertext));
    fj_secure_zero(tag, sizeof(tag));
    return ok;
}

bool fj_hmac_credential_open(const fj_hmac_credential_t *record,
                             const uint8_t root[32],
                             uint8_t material[FJ_HMAC_MATERIAL_LEN]) {
    if (!material) return false;
    if (!record || !root) { fj_secure_zero(material, FJ_HMAC_MATERIAL_LEN); return false; }
    uint8_t key[32] = {0}, aad[HMAC_AAD_LENGTH] = {0};
    size_t n = credential_aad(record, aad);
    bool ok = fj_hkdf(root, "Fjaeger hmac credential v1", record->credential_id,
                      sizeof(record->credential_id), key) &&
              fj_aes_gcm_decrypt_with_aad(key, record->nonce, record->tag, aad, n,
                                          record->ciphertext, FJ_HMAC_MATERIAL_LEN, material);
    if (!ok) fj_secure_zero(material, FJ_HMAC_MATERIAL_LEN);
    fj_secure_zero(key, sizeof(key));
    fj_secure_zero(aad, sizeof(aad));
    return ok;
}
