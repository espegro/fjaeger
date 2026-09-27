#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "cbor.h"
#include "crypto.h"
#include "ctap2.h"
#include "keys.h"
#include "state.h"

static fj_ctap2_cred_t persisted[FJ_CTAP2_CREDS];
static uint8_t random_byte = 1;

fj_state_t fj_state_get(void) { return FJ_STATE_UNLOCKED; }

void fj_state_brute_success(fj_brute_ctx_t ctx) { (void)ctx; }
void fj_state_brute_failure(fj_brute_ctx_t ctx) { (void)ctx; }
bool fj_state_brute_ok(fj_brute_ctx_t ctx) { (void)ctx; return true; }

unsigned fj_keys_active_profile(void) { return 0; }

void fj_keys_ctap2_load(fj_ctap2_cred_t *out) {
    memcpy(out, persisted, sizeof(persisted));
}

bool fj_keys_ctap2_save(const fj_ctap2_cred_t *creds) {
    memcpy(persisted, creds, sizeof(persisted));
    return true;
}

void fj_random(void *buf, size_t len) {
    uint8_t *p = buf;
    while (len--) *p++ = random_byte++;
}

void fj_sha256(const uint8_t *data, size_t len, uint8_t out[32]) {
    memset(out, 0, 32);
    for (size_t i = 0; i < len; i++) out[i % 32] ^= data[i];
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

bool fj_state_cwk(uint8_t out[32]) {
    memset(out, 0x5A, 32);
    return true;
}

bool fj_aes_gcm_encrypt(const uint8_t key[32], const uint8_t nonce[12],
                        const uint8_t *in, size_t len,
                        uint8_t *out, uint8_t tag[16]) {
    (void)key; (void)nonce;
    memcpy(out, in, len);
    memset(tag, 0, 16);
    return true;
}

bool fj_aes_gcm_decrypt(const uint8_t key[32], const uint8_t nonce[12],
                        const uint8_t tag[16],
                        const uint8_t *in, size_t len, uint8_t *out) {
    (void)key; (void)nonce; (void)tag;
    memcpy(out, in, len);
    return true;
}

bool fj_hmac_sha256(const uint8_t *key, size_t key_len,
                    const uint8_t *data, size_t len,
                    uint8_t out[32]) {
    (void)key; (void)key_len; (void)data; (void)len;
    memset(out, 0xBB, 32);
    return true;
}

bool fj_keys_get_security(fj_security_t *s) { memset(s, 0, sizeof(*s)); return true; }
bool fj_keys_set_security(const fj_security_t *s) { (void)s; return true; }
bool fj_keys_pin_configured(void) { return false; }
bool fj_state_ctap2_verify(const uint8_t verifier[16]) { (void)verifier; return true; }
void fj_led_sign(void) {}

bool fj_ecdsa_sign(const uint8_t private_key[32], const uint8_t digest[32],
                   uint8_t signature[64]) {
    (void)private_key;
    (void)digest;
    memset(signature, 0x33, 64);
    return true;
}

bool fj_ecdsa_signature_der(const uint8_t signature[64], uint8_t *out,
                            size_t out_cap, size_t *out_len) {
    static const uint8_t der[] = {0x30, 0x06, 0x02, 0x01,
                                  0x01, 0x02, 0x01, 0x01};
    (void)signature;
    if (out_cap < sizeof(der)) return false;
    memcpy(out, der, sizeof(der));
    *out_len = sizeof(der);
    return true;
}

static size_t make_request(uint8_t *buf, size_t cap) {
    uint8_t hash[32] = {0};
    uint8_t user_id[32] = {0};
    fj_cbor_writer w;
    fj_cbor_writer_init(&w, buf + 1, cap - 1);
    buf[0] = 0x01;
    fj_cbor_map(&w, 4);
    fj_cbor_uint(&w, 1); fj_cbor_bstr(&w, hash, sizeof(hash));
    fj_cbor_uint(&w, 2); fj_cbor_map(&w, 1);
    fj_cbor_tstr(&w, "id"); fj_cbor_tstr(&w, "ssh:");
    fj_cbor_uint(&w, 3); fj_cbor_map(&w, 3);
    fj_cbor_tstr(&w, "id"); fj_cbor_bstr(&w, user_id, sizeof(user_id));
    fj_cbor_tstr(&w, "name"); fj_cbor_tstr(&w, "openssh");
    fj_cbor_tstr(&w, "displayName"); fj_cbor_tstr(&w, "openssh");
    fj_cbor_uint(&w, 4); fj_cbor_array(&w, 1); fj_cbor_map(&w, 2);
    fj_cbor_tstr(&w, "alg"); fj_cbor_neg(&w, 6);
    fj_cbor_tstr(&w, "type"); fj_cbor_tstr(&w, "public-key");
    assert(fj_cbor_ok(&w));
    return w.len + 1;
}

static size_t assertion_request(uint8_t *buf, size_t cap) {
    uint8_t hash[32] = {0};
    uint8_t credential_id[FJ_CRED_ID_LEN];
    for (size_t i = 0; i < sizeof(credential_id); i++)
        credential_id[i] = (uint8_t)(i + 1);

    fj_cbor_writer w;
    fj_cbor_writer_init(&w, buf + 1, cap - 1);
    buf[0] = 0x02;
    fj_cbor_map(&w, 3);
    fj_cbor_uint(&w, 1); fj_cbor_tstr(&w, "ssh:");
    fj_cbor_uint(&w, 2); fj_cbor_bstr(&w, hash, sizeof(hash));
    fj_cbor_uint(&w, 3); fj_cbor_array(&w, 1); fj_cbor_map(&w, 2);
    fj_cbor_tstr(&w, "type"); fj_cbor_tstr(&w, "public-key");
    fj_cbor_tstr(&w, "id");
    fj_cbor_bstr(&w, credential_id, sizeof(credential_id));
    assert(fj_cbor_ok(&w));
    return w.len + 1;
}

static void assert_response_map(const uint8_t *response, size_t len,
                                size_t expected_pairs) {
    assert(len > 1 && response[0] == 0);
    fj_cbor_reader r;
    fj_cbor_item item;
    fj_cbor_reader_init(&r, response + 1, len - 1);
    assert(fj_cbor_next(&r, &item));
    assert(item.type == FJ_CBOR_MAP && item.val == expected_pairs);
}

int main(void) {
    uint8_t request[512];
    uint8_t response[512];
    size_t len;

    memset(persisted, 0, sizeof(persisted));
    fj_ctap2_init();

    request[0] = 0x04;
    len = fj_ctap2_dispatch(request, 1, response, sizeof(response));
    assert_response_map(response, len, 6);

    size_t request_len = make_request(request, sizeof(request));
    len = fj_ctap2_dispatch(request, request_len, response, sizeof(response));
    assert_response_map(response, len, 3);
    fj_ctap2_task();
    assert(persisted[0].in_use);

    request_len = assertion_request(request, sizeof(request));
    len = fj_ctap2_dispatch(request, request_len, response, sizeof(response));
    assert_response_map(response, len, 3);
    /* The credential descriptor must use deterministic CBOR key ordering:
     * the two-byte "id" key precedes the four-byte "type" key. */
    assert(len > 7);
    assert(response[2] == 0x01 && response[3] == 0xa2);
    assert(response[4] == 0x62 && response[5] == 'i' && response[6] == 'd');

    /* Factory reset must invalidate the live credential cache immediately,
     * without waiting for a reboot. */
    fj_ctap2_forget_all();
    len = fj_ctap2_dispatch(request, request_len, response, sizeof(response));
    assert(len == 1 && response[0] != 0);

    puts("ctap2 host tests: ok");
    return 0;
}
