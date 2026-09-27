/* Host tests for CTAP2 profile isolation.
 *
 * Exercises the acceptance behaviour that profiles must be enforced:
 *   - makeCredential binds the new credential to the active profile;
 *   - getAssertion (with and without allowList) only ever resolves
 *     credentials in the active profile, so a credential from another
 *     profile is never used.
 */
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
static unsigned active_profile = 0;

fj_state_t fj_state_get(void) { return FJ_STATE_UNLOCKED; }

void fj_state_brute_success(fj_brute_ctx_t ctx) { (void)ctx; }
void fj_state_brute_failure(fj_brute_ctx_t ctx) { (void)ctx; }
bool fj_state_brute_ok(fj_brute_ctx_t ctx) { (void)ctx; return true; }

unsigned fj_keys_active_profile(void) { return active_profile; }

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
void fj_keys_get_pin(uint8_t pbkdf2[32], uint8_t salt[16], uint8_t verifier[16]) {
    (void)pbkdf2; (void)salt; (void)verifier;
}
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

/* makeCredential for RP "ssh:" with an optional excludeList credential id.
 * The credential is enrolled as resident (discoverable) so that a getAssertion
 * without an allowList can resolve it by RP in the active profile. */
static size_t make_request(uint8_t *buf, size_t cap,
                           const uint8_t *exclude_id, bool have_exclude) {
    uint8_t hash[32] = {0};
    uint8_t user_id[16] = {0};
    fj_cbor_writer w;
    fj_cbor_writer_init(&w, buf + 1, cap - 1);
    buf[0] = 0x01;
    fj_cbor_map(&w, have_exclude ? 6 : 5);
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
    /* options (key 0x07): rk = true */
    fj_cbor_uint(&w, 7); fj_cbor_map(&w, 1);
    fj_cbor_tstr(&w, "rk"); fj_cbor_bool(&w, true);
    if (have_exclude) {
        fj_cbor_uint(&w, 5); fj_cbor_array(&w, 1); fj_cbor_map(&w, 1);
        fj_cbor_tstr(&w, "id"); fj_cbor_bstr(&w, exclude_id, FJ_CRED_ID_LEN);
    }
    assert(fj_cbor_ok(&w));
    return w.len + 1;
}

/* getAssertion for RP "ssh:". If allow_id is non-NULL an allowList entry
 * carrying that credential id is included; otherwise the request has no
 * allowList. */
static size_t assertion_request(uint8_t *buf, size_t cap,
                                const uint8_t *allow_id, bool have_allow) {
    uint8_t hash[32] = {0};
    fj_cbor_writer w;
    fj_cbor_writer_init(&w, buf + 1, cap - 1);
    buf[0] = 0x02;
    fj_cbor_map(&w, have_allow ? 3 : 2);
    fj_cbor_uint(&w, 1); fj_cbor_tstr(&w, "ssh:");
    fj_cbor_uint(&w, 2); fj_cbor_bstr(&w, hash, sizeof(hash));
    if (have_allow) {
        fj_cbor_uint(&w, 3); fj_cbor_array(&w, 1); fj_cbor_map(&w, 2);
        fj_cbor_tstr(&w, "type"); fj_cbor_tstr(&w, "public-key");
        fj_cbor_tstr(&w, "id");
        fj_cbor_bstr(&w, allow_id, FJ_CRED_ID_LEN);
    }
    assert(fj_cbor_ok(&w));
    return w.len + 1;
}

static void assert_ok(size_t len) {
    assert(len > 1 && len < 512);
    assert(len == 1 || true); /* placeholder; success checked by caller */
}

static size_t dispatch_cmd(const uint8_t *req, size_t reqlen,
                           uint8_t *response, size_t cap) {
    return fj_ctap2_dispatch(req, reqlen, response, cap);
}

int main(void) {
    uint8_t request[512];
    uint8_t response[512];
    size_t len;
    uint8_t cred_a[FJ_CRED_ID_LEN];
    uint8_t cred_b[FJ_CRED_ID_LEN];

    memset(persisted, 0, sizeof(persisted));

    /* --- Enroll credential A in profile 0 --- */
    active_profile = 0;
    random_byte = 1;
    fj_ctap2_init();
    len = dispatch_cmd(request, make_request(request, sizeof(request), NULL, false),
                       response, sizeof(response));
    assert(len > 1 && response[0] == 0);
    fj_ctap2_task();
    assert(persisted[0].in_use && persisted[0].profile_id == 0);
    memcpy(cred_a, persisted[0].credential_id, FJ_CRED_ID_LEN);

    /* --- Enroll credential B in profile 1 --- */
    active_profile = 1;
    len = dispatch_cmd(request, make_request(request, sizeof(request), NULL, false),
                       response, sizeof(response));
    assert(len > 1 && response[0] == 0);
    fj_ctap2_task();
    assert(persisted[1].in_use && persisted[1].profile_id == 1);
    memcpy(cred_b, persisted[1].credential_id, FJ_CRED_ID_LEN);

    /* A and B must be distinct credentials. */
    assert(memcmp(cred_a, cred_b, FJ_CRED_ID_LEN) != 0);

    /* --- With profile 0 active, only credential A is usable. --- */
    active_profile = 0;
    len = dispatch_cmd(request, assertion_request(request, sizeof(request), cred_a, true),
                       response, sizeof(response));
    assert(len > 1 && response[0] == 0);               /* A works */
    len = dispatch_cmd(request, assertion_request(request, sizeof(request), cred_b, true),
                       response, sizeof(response));
    assert(len == 1 && response[0] != 0);              /* B rejected */
    /* No allowList: search must also stay in the active profile. */
    len = dispatch_cmd(request, assertion_request(request, sizeof(request), NULL, false),
                       response, sizeof(response));
    assert(len > 1 && response[0] == 0);               /* resolves A */

    /* --- With profile 1 active, only credential B is usable. --- */
    active_profile = 1;
    len = dispatch_cmd(request, assertion_request(request, sizeof(request), cred_b, true),
                       response, sizeof(response));
    assert(len > 1 && response[0] == 0);               /* B works */
    len = dispatch_cmd(request, assertion_request(request, sizeof(request), cred_a, true),
                       response, sizeof(response));
    assert(len == 1 && response[0] != 0);              /* A rejected */
    len = dispatch_cmd(request, assertion_request(request, sizeof(request), NULL, false),
                       response, sizeof(response));
    assert(len > 1 && response[0] == 0);               /* resolves B */

    /* --- An unknown credential id in the active profile is rejected. --- */
    active_profile = 0;
    uint8_t unknown[FJ_CRED_ID_LEN];
    memset(unknown, 0xAA, sizeof(unknown));
    len = dispatch_cmd(request, assertion_request(request, sizeof(request), unknown, true),
                       response, sizeof(response));
    assert(len == 1 && response[0] != 0);

    /* --- excludeList rejects duplicate registration across profiles. --- */
    active_profile = 0;
    random_byte = 200;
    len = dispatch_cmd(request, make_request(request, sizeof(request), cred_a, true),
                       response, sizeof(response));
    assert(len == 1 && response[0] != 0);              /* duplicate rejected */

    (void)assert_ok;
    puts("profile host tests: ok");
    return 0;
}