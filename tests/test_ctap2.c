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
static bool ctap2_pin_configured = true;
static unsigned ed25519_sign_count = 0;

fj_state_t fj_state_get(void) { return FJ_STATE_UNLOCKED; }
bool fj_state_ctap2_pin_configured(void) { return ctap2_pin_configured; }

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

/* Test-only AES-GCM oracle whose tag depends on key, nonce, AAD and data,
 * so the resident-credential AAD binding is genuinely authenticated in CI
 * (production uses real mbedTLS AES-GCM). Deterministic, not cryptographic. */
static uint64_t test_gcm_hash(const uint8_t *key, const uint8_t *nonce,
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

static void test_gcm_tag(const uint8_t *key, const uint8_t *nonce,
                         const uint8_t *aad, size_t aad_len,
                         const uint8_t *data, size_t len, uint8_t tag[16]) {
    /* Two seeded hashes (never swap the key/nonce pointers, which would read
     * past the 12-byte nonce) give a spread across all 16 tag bytes. */
    uint64_t a = test_gcm_hash(key, nonce, aad, aad_len, data, len, 0x0000000000000000ull);
    uint64_t b = test_gcm_hash(key, nonce, aad, aad_len, data, len, 0x9e3779b97f4a7c15ull);
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
    test_gcm_tag(key, nonce, aad, aad_len, in, len, tag);
    return true;
}

bool fj_aes_gcm_decrypt_with_aad(const uint8_t key[32], const uint8_t nonce[12],
                                 const uint8_t tag[16],
                                 const uint8_t *aad, size_t aad_len,
                                 const uint8_t *in, size_t len, uint8_t *out) {
    uint8_t exp[16];
    int diff = 0;
    test_gcm_tag(key, nonce, aad, aad_len, in, len, exp);
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
                    const uint8_t *data, size_t len,
                    uint8_t out[32]) {
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

bool fj_ed25519_generate(uint8_t seed[32], uint8_t public_key[32]) {
    memset(seed, 0x55, 32);
    memset(public_key, 0x66, 32);
    return true;
}

bool fj_ed25519_sign(const uint8_t seed[32], const uint8_t *message,
                     size_t message_len, uint8_t signature[64]) {
    (void)seed; (void)message; (void)message_len;
    memset(signature, 0x77, 64);
    ed25519_sign_count++;
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

/* makeCredential request that creates a RESIDENT (rk) credential for "ssh:". */
static size_t resident_request(uint8_t *buf, size_t cap, bool ed25519) {
    size_t p = 0;
    buf[p++] = 0x01;                 /* authenticatorMakeCredential */
    buf[p++] = 0xa6;                 /* map(6) */
    buf[p++] = 0x01; buf[p++] = 0x58; buf[p++] = 0x20;                /* 1 clientDataHash */
    for (int i = 0; i < 32; i++) buf[p++] = (uint8_t)(0xAB + i);
    buf[p++] = 0x02; buf[p++] = 0xa1; buf[p++] = 0x62;                /* 2 rp {id:"ssh:"} */
    buf[p++] = 'i'; buf[p++] = 'd'; buf[p++] = 0x64;
    buf[p++] = 's'; buf[p++] = 's'; buf[p++] = 'h'; buf[p++] = ':';
    buf[p++] = 0x03; buf[p++] = 0xa3;                                /* 3 user */
    buf[p++] = 0x62; buf[p++] = 'i'; buf[p++] = 'd'; buf[p++] = 0x58; buf[p++] = 0x20;
    for (int i = 0; i < 32; i++) buf[p++] = 0xCD;
    buf[p++] = 0x64; memcpy(buf + p, "name", 4); p += 4;
    buf[p++] = 0x67; memcpy(buf + p, "espegro", 7); p += 7;
    buf[p++] = 0x6b; memcpy(buf + p, "displayName", 11); p += 11;
    buf[p++] = 0x67; memcpy(buf + p, "espegro", 7); p += 7;
    buf[p++] = 0x04; buf[p++] = 0x81; buf[p++] = 0xa2;                /* 4 pubKeyCredParams */
    buf[p++] = 0x63; memcpy(buf + p, "alg", 3); p += 3;
    buf[p++] = ed25519 ? 0x27 : 0x26;                    /* alg -8 / -7 */
    buf[p++] = 0x64; memcpy(buf + p, "type", 4); p += 4;
    buf[p++] = 0x6a; memcpy(buf + p, "public-key", 10); p += 10;
    buf[p++] = 0x05; buf[p++] = 0x80;                                /* 5 excludeList [] */
    buf[p++] = 0x07; buf[p++] = 0xa1; buf[p++] = 0x62;               /* 7 options {"rk":true} */
    buf[p++] = 'r'; buf[p++] = 'k'; buf[p++] = 0xf5;
    assert(p <= cap);
    return p;
}

/* Discovery getAssertion (no allowList) for resident lookup by RP "ssh:". */
static size_t discovery_request(uint8_t *buf, size_t cap) {
    uint8_t hash[32];
    for (int i = 0; i < 32; i++) hash[i] = (uint8_t)i;
    fj_cbor_writer w;
    fj_cbor_writer_init(&w, buf + 1, cap - 1);
    buf[0] = 0x02;
    fj_cbor_map(&w, 2);
    fj_cbor_uint(&w, 1); fj_cbor_tstr(&w, "ssh:");
    fj_cbor_uint(&w, 2); fj_cbor_bstr(&w, hash, sizeof(hash));
    assert(fj_cbor_ok(&w));
    return w.len + 1;
}

/* getAssertion with an allowList carrying the given credential id. */
static size_t allow_request(uint8_t *buf, size_t cap, const uint8_t *id) {
    uint8_t hash[32];
    for (int i = 0; i < 32; i++) hash[i] = (uint8_t)i;
    fj_cbor_writer w;
    fj_cbor_writer_init(&w, buf + 1, cap - 1);
    buf[0] = 0x02;
    fj_cbor_map(&w, 3);
    fj_cbor_uint(&w, 1); fj_cbor_tstr(&w, "ssh:");
    fj_cbor_uint(&w, 2); fj_cbor_bstr(&w, hash, sizeof(hash));
    fj_cbor_uint(&w, 3); fj_cbor_array(&w, 1); fj_cbor_map(&w, 2);
    fj_cbor_tstr(&w, "type"); fj_cbor_tstr(&w, "public-key");
    fj_cbor_tstr(&w, "id"); fj_cbor_bstr(&w, id, FJ_CRED_ID_LEN);
    assert(fj_cbor_ok(&w));
    return w.len + 1;
}

/* Resident AAD regression (FJ-N001): enroll a resident key, persist, reload,
 * sign, and verify that each AAD-bound immutable field is authenticated. */
static void test_resident_aad(void) {
    uint8_t request[512], response[512];
    uint8_t saved[sizeof(persisted[0])];
    size_t len;

    memset(persisted, 0, sizeof(persisted));
    fj_ctap2_init();

    /* enroll a resident credential and persist it */
    len = resident_request(request, sizeof(request), false);
    len = fj_ctap2_dispatch(request, len, response, sizeof(response));
    assert(len > 1 && response[0] == 0);          /* makeCredential ok */
    fj_ctap2_task();                               /* persist to flash store */
    assert(persisted[0].in_use && persisted[0].resident);

    /* sign before reload */
    len = discovery_request(request, sizeof(request));
    len = fj_ctap2_dispatch(request, len, response, sizeof(response));
    assert(len > 1 && response[0] == 0);

    /* reload from flash, then sign again (decrypt must succeed) */
    fj_ctap2_init();
    len = discovery_request(request, sizeof(request));
    len = fj_ctap2_dispatch(request, len, response, sizeof(response));
    assert(len > 1 && response[0] == 0);

#define FJ_TAMPER(expr) do {         memcpy(saved, &persisted[0], sizeof(saved));         (expr);                                              fj_ctap2_init();                                     len = allow_request(request, sizeof(request), persisted[0].credential_id);         len = fj_ctap2_dispatch(request, len, response, sizeof(response));         assert(len == 1 && response[0] != 0);        /* binding/reject */         memcpy(&persisted[0], saved, sizeof(saved)); /* restore */         fj_ctap2_init();                                     len = discovery_request(request, sizeof(request));         len = fj_ctap2_dispatch(request, len, response, sizeof(response));         assert(len > 1 && response[0] == 0);         /* still works */     } while (0)

    FJ_TAMPER(persisted[0].public_key[1] ^= 0x01);   /* GCM auth fail */
    FJ_TAMPER(persisted[0].resident = 0);            /* GCM auth fail */
    FJ_TAMPER(persisted[0].rp_id_hash[0] ^= 0x01);   /* lookup reject */
    FJ_TAMPER(persisted[0].profile_id = 9);          /* lookup reject */
#undef FJ_TAMPER

    /* FJ: deleting the credential is active-profile scoped; after persist +
     * reload it is gone, and a second delete fails. */
    {
        uint8_t id[FJ_CRED_ID_LEN];
        memcpy(id, persisted[0].credential_id, FJ_CRED_ID_LEN);
        assert(fj_ctap2_delete_cred(0, id));
        assert(!fj_ctap2_delete_cred(0, id));          /* already gone */
        fj_ctap2_task();                               /* persist the deletion */
        fj_ctap2_init();                               /* reload */
        len = discovery_request(request, sizeof(request));
        len = fj_ctap2_dispatch(request, len, response, sizeof(response));
        assert(len == 1 && response[0] != 0);          /* no resident cred left */
    }

    puts("resident AAD round-trip + tamper: ok");
}

static void test_ed25519_credential(void) {
    uint8_t request[512], response[512];
    memset(persisted, 0, sizeof(persisted));
    ed25519_sign_count = 0;
    fj_ctap2_init();

    size_t len = resident_request(request, sizeof(request), true);
    len = fj_ctap2_dispatch(request, len, response, sizeof(response));
    assert(len > 1 && response[0] == 0);
    fj_ctap2_task();
    assert(persisted[0].in_use && persisted[0].public_key[0] == 0xed);

    len = discovery_request(request, sizeof(request));
    len = fj_ctap2_dispatch(request, len, response, sizeof(response));
    assert(len > 1 && response[0] == 0);
    assert(ed25519_sign_count == 1);

    /* Ed25519 assertions carry a raw 64-byte signature, not ECDSA DER. */
    fj_cbor_reader r;
    fj_cbor_item root;
    fj_cbor_reader_init(&r, response + 1, len - 1);
    assert(fj_cbor_next(&r, &root) && root.type == FJ_CBOR_MAP);
    bool found_signature = false;
    for (uint64_t i = 0; i < root.val; i++) {
        fj_cbor_item key, value;
        assert(fj_cbor_next(&r, &key));
        assert(fj_cbor_next(&r, &value));
        if (key.type == FJ_CBOR_UINT && key.val == 3) {
            assert(value.type == FJ_CBOR_BSTR && value.val == 64);
            found_signature = true;
        }
        assert(fj_cbor_skip(&r, &value));
    }
    assert(found_signature);
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

static void assert_get_info_client_pin(const uint8_t *response, size_t len,
                                       bool expected) {
    static const uint8_t key[] = {0x69, 'c', 'l', 'i', 'e', 'n', 't', 'P', 'i', 'n'};
    for (size_t i = 0; i + sizeof(key) < len; i++) {
        if (memcmp(response + i, key, sizeof(key)) == 0) {
            assert(response[i + sizeof(key)] == (expected ? 0xf5 : 0xf4));
            return;
        }
    }
    assert(!"clientPin missing from GetInfo");
}

static void test_cbor_limits(void) {
    uint8_t nested[FJ_CBOR_MAX_DEPTH + 2];
    fj_cbor_reader r;
    fj_cbor_item item;

    /* Exactly the configured number of nested containers is accepted. */
    memset(nested, 0x81, FJ_CBOR_MAX_DEPTH);
    nested[FJ_CBOR_MAX_DEPTH] = 0xf6; /* null */
    fj_cbor_reader_init(&r, nested, FJ_CBOR_MAX_DEPTH + 1);
    assert(fj_cbor_next(&r, &item));
    assert(fj_cbor_skip(&r, &item));

    /* One more level is rejected before it can consume unbounded stack. */
    memset(nested, 0x81, FJ_CBOR_MAX_DEPTH + 1);
    nested[FJ_CBOR_MAX_DEPTH + 1] = 0xf6;
    fj_cbor_reader_init(&r, nested, sizeof(nested));
    assert(fj_cbor_next(&r, &item));
    assert(!fj_cbor_skip(&r, &item));

    /* A declared payload larger than the input must never wrap a size check. */
    static const uint8_t huge_bstr[] = {
        0x5b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
    };
    fj_cbor_reader_init(&r, huge_bstr, sizeof(huge_bstr));
    assert(fj_cbor_next(&r, &item));
    assert(!fj_cbor_skip(&r, &item));
}

int main(void) {
    uint8_t request[512];
    uint8_t response[512];
    size_t len;

    memset(persisted, 0, sizeof(persisted));
    fj_ctap2_init();

    test_cbor_limits();

    request[0] = 0x04;
    ctap2_pin_configured = false;
    len = fj_ctap2_dispatch(request, 1, response, sizeof(response));
    assert_response_map(response, len, 6);
    assert_get_info_client_pin(response, len, false);
    ctap2_pin_configured = true;
    len = fj_ctap2_dispatch(request, 1, response, sizeof(response));
    assert_get_info_client_pin(response, len, true);

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

    test_resident_aad();
    test_ed25519_credential();

    /* Factory reset must invalidate the live credential cache immediately,
     * without waiting for a reboot. */
    fj_ctap2_forget_all();
    len = fj_ctap2_dispatch(request, request_len, response, sizeof(response));
    assert(len == 1 && response[0] != 0);

    puts("ctap2 host tests: ok");
    return 0;
}
