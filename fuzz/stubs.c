/* Stubbed firmware layers so the CTAP2/CBOR parsers can be fuzzed on host
 * (real mbedTLS/Pico SDK not used). Mirrors tests/test_ctap2.c. */
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include "cbor.h"
#include "crypto.h"
#include "ctap2.h"
#include "keys.h"
#include "state.h"

fj_ctap2_cred_t fuzz_persisted[FJ_CTAP2_CREDS];
static uint8_t random_byte = 1;

fj_state_t fj_state_get(void) { return FJ_STATE_UNLOCKED; }
void fj_state_brute_success(fj_brute_ctx_t ctx) { (void)ctx; }
void fj_state_brute_failure(fj_brute_ctx_t ctx) { (void)ctx; }
bool fj_state_brute_ok(fj_brute_ctx_t ctx) { (void)ctx; return true; }
unsigned fj_keys_active_profile(void) { return 0; }

void fj_keys_ctap2_load(fj_ctap2_cred_t *out) {
    memcpy(out, fuzz_persisted, sizeof(fuzz_persisted));
}
bool fj_keys_ctap2_save(const fj_ctap2_cred_t *creds) {
    memcpy(fuzz_persisted, creds, sizeof(fuzz_persisted));
    return true;
}

void fj_random(void *buf, size_t len) {
    uint8_t *p = buf;
    while (len--) *p++ = random_byte++;
}
void fj_sha256(const uint8_t *data, size_t len, uint8_t out[32]) {
    size_t i;
    memset(out, 0, 32);
    for (i = 0; i < len; i++) out[i % 32] ^= data[i];
}
bool fj_ecdsa_generate_private(uint8_t private_key[32]) {
    memset(private_key, 0x42, 32);
    private_key[31] = 1;
    return true;
}
bool fj_ecdsa_pubkey(const uint8_t private_key[32], uint8_t pub[65]) {
    (void)private_key;
    pub[0] = 4;
    memset(pub + 1, 0x11, 32);
    memset(pub + 33, 0x22, 32);
    return true;
}
bool fj_ecdh_shared_secret(const uint8_t private_key[32], const uint8_t peer_pub[65],
                           uint8_t out[32]) {
    (void)private_key; (void)peer_pub;
    memset(out, 0xAA, 32);
    return true;
}
bool fj_aes_cbc(const uint8_t key[32], const uint8_t iv[16],
                uint8_t *buf, size_t len, bool encrypt) {
    (void)key; (void)iv; (void)buf; (void)len; (void)encrypt;
    return true;
}
bool fj_state_cwk(uint8_t out[32]) { memset(out, 0x5A, 32); return true; }

static uint64_t fz_gcm_hash(const uint8_t *key, const uint8_t *nonce,
                            const uint8_t *aad, size_t aad_len,
                            const uint8_t *data, size_t len, uint64_t x) {
    uint64_t h = 0xcbf29ce484222325ull ^ x;
    size_t i;
    for (i = 0; i < 32; i++)          { h ^= key[i]; h *= 0x100000001b3ull; }
    for (i = 0; i < 12; i++)          { h ^= nonce[i]; h *= 0x100000001b3ull; }
    for (i = 0; i < 8; i++)           { h ^= (uint8_t)(aad_len >> (8 * i)); h *= 0x100000001b3ull; }
    for (i = 0; i < aad_len; i++)     { h ^= aad[i]; h *= 0x100000001b3ull; }
    for (i = 0; i < len; i++)         { h ^= data[i]; h *= 0x100000001b3ull; }
    h ^= h >> 33; h *= 0xff51afd7ed558ccdull; h ^= h >> 33;
    return h;
}
static void fz_gcm_tag(const uint8_t *key, const uint8_t *nonce,
                       const uint8_t *aad, size_t aad_len,
                       const uint8_t *data, size_t len, uint8_t tag[16]) {
    uint64_t a = fz_gcm_hash(key, nonce, aad, aad_len, data, len, 0);
    uint64_t b = fz_gcm_hash(key, nonce, aad, aad_len, data, len, 0x9e3779b97f4a7c15ull);
    size_t i;
    for (i = 0; i < 8; i++) tag[i]     = (uint8_t)(a >> (8 * i));
    for (i = 0; i < 8; i++) tag[8 + i] = (uint8_t)(b >> (8 * i));
    tag[15] ^= 0x5a;
}
bool fj_aes_gcm_encrypt_with_aad(const uint8_t key[32], const uint8_t nonce[12],
                                 const uint8_t *aad, size_t aad_len,
                                 const uint8_t *in, size_t len,
                                 uint8_t *out, uint8_t tag[16]) {
    memcpy(out, in, len);
    fz_gcm_tag(key, nonce, aad, aad_len, in, len, tag);
    return true;
}
bool fj_aes_gcm_decrypt_with_aad(const uint8_t key[32], const uint8_t nonce[12],
                                 const uint8_t tag[16],
                                 const uint8_t *aad, size_t aad_len,
                                 const uint8_t *in, size_t len, uint8_t *out) {
    uint8_t exp[16];
    int diff = 0;
    fz_gcm_tag(key, nonce, aad, aad_len, in, len, exp);
    for (size_t i = 0; i < 16; i++) diff |= tag[i] ^ exp[i];
    if (diff) return false;
    memcpy(out, in, len);
    return true;
}
bool fj_aes_gcm_encrypt(const uint8_t key[32], const uint8_t nonce[12],
                        const uint8_t *in, size_t len,
                        uint8_t *out, uint8_t tag[16]) {
    return fj_aes_gcm_encrypt_with_aad(key, nonce, NULL, 0, in, len, out, tag);
}
bool fj_aes_gcm_decrypt(const uint8_t key[32], const uint8_t nonce[12],
                        const uint8_t tag[16],
                        const uint8_t *in, size_t len, uint8_t *out) {
    return fj_aes_gcm_decrypt_with_aad(key, nonce, tag, NULL, 0, in, len, out);
}
bool fj_hmac_sha256(const uint8_t *key, size_t key_len,
                    const uint8_t *data, size_t len, uint8_t out[32]) {
    (void)key; (void)key_len; (void)data; (void)len;
    memset(out, 0, 32);
    return true;
}
bool fj_ct_equal(const void *a, const void *b, size_t n) {
    const uint8_t *x = a, *y = b;
    uint8_t d = 0;
    for (size_t i = 0; i < n; i++) d |= x[i] ^ y[i];
    return d == 0;
}
bool fj_keys_get_security(fj_security_t *s) { memset(s, 0, sizeof(*s)); return true; }
bool fj_keys_set_security(const fj_security_t *s) { (void)s; return true; }
bool fj_keys_pin_configured(void) { return false; }
bool fj_state_ctap2_verify(const uint8_t verifier[16]) { (void)verifier; return true; }
void fj_led_sign(void) {}
bool fj_ecdsa_sign(const uint8_t private_key[32], const uint8_t digest[32],
                   uint8_t signature[64]) {
    (void)private_key; (void)digest;
    memset(signature, 0x33, 64);
    return true;
}
bool fj_ecdsa_signature_der(const uint8_t signature[64], uint8_t *out,
                            size_t out_cap, size_t *out_len) {
    static const uint8_t der[] = {0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01};
    (void)signature;
    if (out_cap < sizeof(der)) return false;
    memcpy(out, der, sizeof(der));
    *out_len = sizeof(der);
    return true;
}
