/* Host test for the profile-erase / deferred-flush interaction.
 *
 * Verifies the TODO requirement that erasing a profile updates both the
 * live CTAP2 cache and the persistent store as one consistent operation,
 * so that a deferred flash flush can never write erased credentials back
 * to flash.
 *
 * Scenario:
 *   - persistent store has credA (profile 1) and credB (profile 0);
 *   - profile 0 is active, so a makeCredential enrolls credC into the live
 *     cache (marked dirty, not yet flushed);
 *   - profile 1 is selected and profile 0 is erased
 *     (fj_state_profile_erase -> forget_profile + persistent erase);
 *   - fj_ctap2_task() runs the deferred flush;
 *   - credA (profile 1) must survive; credB and credC (profile 0) must be
 *     gone from the persistent store after the flush.
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
#include "pico/time.h"

/* --- simulated persistent store ------------------------------------- */
static fj_ctap2_cred_t persisted[FJ_CTAP2_CREDS];

void fj_keys_ctap2_load(fj_ctap2_cred_t *out) {
    memcpy(out, persisted, sizeof(persisted));
}

bool fj_keys_ctap2_save(const fj_ctap2_cred_t *creds) {
    memcpy(persisted, creds, sizeof(persisted));
    return true;
}

/* Simulate what keys.c does on erase: drop the profile's credentials from
 * the persistent store. */
bool fj_keys_profile_erase(unsigned profile) {
    for (unsigned i = 0; i < FJ_CTAP2_CREDS; i++) {
        if (persisted[i].in_use && persisted[i].profile_id == profile)
            memset(&persisted[i], 0, sizeof(fj_ctap2_cred_t));
    }
    return true;
}

/* --- misc stubs ------------------------------------------------------ */
static unsigned active_profile = 0;

unsigned fj_keys_active_profile(void) { return active_profile; }

void fj_random(void *buf, size_t len) {
    uint8_t *p = buf;
    for (size_t i = 0; i < len; i++) p[i] = (uint8_t)(i + 1);
}

void fj_sha256(const uint8_t *data, size_t len, uint8_t out[32]) {
    memset(out, 0, 32);
    for (size_t i = 0; i < len; i++) out[i % 32] ^= data[i];
}

bool fj_ecdsa_generate_private(uint8_t k[32]) { memset(k, 0x42, 32); k[31] = 1; return true; }
bool fj_ecdsa_pubkey(const uint8_t k[32], uint8_t pub[65]) {
    (void)k; pub[0] = 4; memset(pub + 1, 0x11, 32); memset(pub + 33, 0x22, 32); return true;
}
bool fj_ecdh_shared_secret(const uint8_t k[32], const uint8_t p[65], uint8_t out[32]) {
    (void)k; (void)p; memset(out, 0xAA, 32); return true;
}
bool fj_aes_cbc(const uint8_t key[32], const uint8_t iv[16], uint8_t *buf, size_t len, bool enc) {
    (void)key; (void)iv; (void)buf; (void)len; (void)enc; return true;
}
bool fj_hmac_sha256(const uint8_t *key, size_t key_len, const uint8_t *data, size_t len, uint8_t out[32]) {
    (void)key; (void)key_len; (void)data; (void)len; memset(out, 0xBB, 32); return true;
}
bool fj_ecdsa_sign(const uint8_t k[32], const uint8_t d[32], uint8_t s[64]) {
    (void)k; (void)d; memset(s, 0x33, 64); return true;
}
bool fj_ecdsa_signature_der(const uint8_t s[64], uint8_t *out, size_t cap, size_t *len) {
    static const uint8_t der[] = {0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01};
    (void)s; if (cap < sizeof(der)) return false;
    memcpy(out, der, sizeof(der)); *len = sizeof(der); return true;
}

/* state.c dependencies (mirroring test_security.c). */
absolute_time_t get_absolute_time(void) { return 0; }
int64_t absolute_time_diff_us(absolute_time_t a, absolute_time_t b) { (void)a; return b; }
void fj_msc_lock(void) {}
/* Store the PIN/PUK so the real state.c unlock path can verify them. */
static uint8_t stored_pin[32];
static uint8_t stored_pin_salt[16];
static uint8_t stored_puk[32];
static uint8_t stored_puk_salt[16];
static bool have_pin = false;
static bool have_puk = false;

/* Deterministic PBKDF2 stand-in (consistent for same pw+salt). */
bool fj_pbkdf2_sha256(const uint8_t *pw, size_t pw_len, const uint8_t *salt,
                      size_t salt_len, uint32_t iter, uint8_t out[32]) {
    memset(out, 0, 32);
    size_t n = 0;
    for (size_t i = 0; i < pw_len; i++) { out[n % 32] ^= (uint8_t)(pw[i] + i); n++; }
    for (size_t i = 0; i < salt_len; i++) out[(n + i) % 32] ^= (uint8_t)(salt[i] + i);
    out[0] ^= (uint8_t)iter;
    return true;
}

bool fj_keys_set_passphrase(const uint8_t pbkdf2_hash[32], const uint8_t salt[16]) {
    memcpy(stored_pin, pbkdf2_hash, 32);
    memcpy(stored_pin_salt, salt, 16);
    have_pin = true;
    return true;
}
bool fj_keys_passphrase_configured(void) { return have_pin; }
void fj_keys_get_passphrase(uint8_t pbkdf2_hash[32], uint8_t salt[16]) {
    memcpy(pbkdf2_hash, stored_pin, 32);
    memcpy(salt, stored_pin_salt, 16);
}
bool fj_keys_set_ctap2_pin(const uint8_t verifier[16]) { (void)verifier; return true; }
bool fj_keys_ctap2_pin_configured(void) { return false; }
void fj_keys_get_ctap2_pin(uint8_t verifier[16]) { (void)verifier; }
void fj_led_pin_lock(void) {}
void fj_led_pin_unlock(void) {}
void fj_led_sign(void) {}
bool fj_keys_get_security(fj_security_t *s) { memset(s, 0, sizeof(*s)); return true; }
bool fj_keys_set_security(const fj_security_t *s) { (void)s; return true; }
bool fj_keys_set_puk(const uint8_t pbkdf2_hash[32], const uint8_t salt[16]) {
    memcpy(stored_puk, pbkdf2_hash, 32);
    memcpy(stored_puk_salt, salt, 16);
    have_puk = true;
    return true;
}
bool fj_keys_get_puk(uint8_t pbkdf2_hash[32], uint8_t salt[16]) {
    if (!have_puk) return false;
    memcpy(pbkdf2_hash, stored_puk, 32);
    memcpy(salt, stored_puk_salt, 16);
    return true;
}
void fj_keys_wipe(void) {
    have_pin = false; have_puk = false;
    memset(stored_pin, 0, sizeof(stored_pin));
    memset(stored_pin_salt, 0, sizeof(stored_pin_salt));
    memset(stored_puk, 0, sizeof(stored_puk));
    memset(stored_puk_salt, 0, sizeof(stored_puk_salt));
}
bool fj_keys_get_timeout(uint32_t *s) { *s = 900; return true; }
bool fj_keys_set_timeout(uint32_t s) { (void)s; return true; }

/* Master key stubs (state.c + ctap2.c dependencies). */
static uint8_t stored_m_enc_pin[32];
static uint8_t stored_m_salt_pin[16];
static uint8_t stored_m_enc_puk[32];
static uint8_t stored_m_salt_puk[16];
static bool have_master = false;
bool fj_keys_master_key_set(void) { return have_master; }
bool fj_keys_set_master_pin_wrap(const uint8_t enc[32], const uint8_t salt[16]) {
    memcpy(stored_m_enc_pin, enc, 32);
    memcpy(stored_m_salt_pin, salt, 16);
    have_master = true;
    return true;
}
bool fj_keys_get_master_pin_wrap(uint8_t enc[32], uint8_t salt[16]) {
    if (!have_master) return false;
    memcpy(enc, stored_m_enc_pin, 32);
    memcpy(salt, stored_m_salt_pin, 16);
    return true;
}
bool fj_keys_set_master_puk_wrap(const uint8_t enc[32], const uint8_t salt[16]) {
    memcpy(stored_m_enc_puk, enc, 32);
    memcpy(stored_m_salt_puk, salt, 16);
    have_master = true;
    return true;
}
bool fj_keys_get_master_puk_wrap(uint8_t enc[32], uint8_t salt[16]) {
    if (!have_master) return false;
    memcpy(enc, stored_m_enc_puk, 32);
    memcpy(salt, stored_m_salt_puk, 16);
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

/* Backup/restore stubs (state.c references them; unused here). */
static uint8_t msc_backup_buf[4096];
static size_t msc_backup_len;
bool fj_msc_backup_write(const uint8_t *data, size_t len) {
    if (!data || len > sizeof(msc_backup_buf)) return false;
    memcpy(msc_backup_buf, data, len);
    msc_backup_len = len;
    return true;
}
bool fj_msc_backup_read(uint8_t *out, size_t cap, size_t *len) {
    if (msc_backup_len == 0 || cap < msc_backup_len) return false;
    memcpy(out, msc_backup_buf, msc_backup_len);
    *len = msc_backup_len;
    return true;
}
bool fj_msc_backup_delete(void) { msc_backup_len = 0; return true; }
bool fj_msc_backup_exists(void) { return msc_backup_len > 0; }
bool fj_keys_backup_fill(fj_backup_payload_t *out) { memset(out, 0, sizeof(*out)); return true; }
bool fj_keys_backup_restore(const fj_backup_payload_t *in) { (void)in; return true; }

/* --- helpers --------------------------------------------------------- */
static unsigned count_profile(unsigned profile) {
    unsigned n = 0;
    for (unsigned i = 0; i < FJ_CTAP2_CREDS; i++)
        if (persisted[i].in_use && persisted[i].profile_id == profile) n++;
    return n;
}

static void seed_store(void) {
    static const uint8_t id_a[FJ_CRED_ID_LEN] = {0x0a, 0x0a, 0x0a, 0x0a, 0x0a, 0x0a, 0x0a, 0x0a,
                                                 0x0a, 0x0a, 0x0a, 0x0a, 0x0a, 0x0a, 0x0a, 0x0a};
    static const uint8_t id_b[FJ_CRED_ID_LEN] = {0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
                                                 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b};
    memset(persisted, 0, sizeof(persisted));
    persisted[0].in_use = true;
    persisted[0].profile_id = 1;
    memcpy(persisted[0].credential_id, id_a, FJ_CRED_ID_LEN);
    persisted[1].in_use = true;
    persisted[1].profile_id = 0;
    memcpy(persisted[1].credential_id, id_b, FJ_CRED_ID_LEN);
}

/* makeCredential request for RP "ssh:" with no excludeList. */
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
    fj_cbor_uint(&w, 3); fj_cbor_map(&w, 1);
    fj_cbor_tstr(&w, "id"); fj_cbor_bstr(&w, user_id, sizeof(user_id));
    fj_cbor_uint(&w, 4); fj_cbor_array(&w, 1); fj_cbor_map(&w, 2);
    fj_cbor_tstr(&w, "alg"); fj_cbor_neg(&w, 6);
    fj_cbor_tstr(&w, "type"); fj_cbor_tstr(&w, "public-key");
    assert(fj_cbor_ok(&w));
    return w.len + 1;
}

int main(void) {
    uint8_t req[512], resp[512];

    seed_store();
    active_profile = 1;
    fj_state_init();          /* unlock the device so makeCredential proceeds */
    assert(fj_state_set_passphrase("testpass1"));
    assert(fj_state_unlock("testpass1"));
    assert(fj_state_get() == FJ_STATE_UNLOCKED);
    fj_ctap2_init();          /* load persisted (A profile 1, B profile 0) */

    /* Enroll credC in profile 0 (live cache, dirty, not yet flushed). */
    active_profile = 0;
    size_t reqlen = make_request(req, sizeof(req));
    size_t rlen = fj_ctap2_dispatch(req, reqlen, resp, sizeof(resp));
    assert(rlen > 1 && resp[0] == 0);
    /* A deferred flush has NOT run yet, so the persisted store is unchanged:
     * it still holds A (profile 1) and B (profile 0) only. */
    assert(count_profile(0) == 1);
    assert(count_profile(1) == 1);

    /* Select profile 1 and erase profile 0. */
    active_profile = 1;
    assert(fj_state_profile_erase(0));

    /* Run the deferred flush that the main loop would trigger. */
    fj_ctap2_task();

    /* The flush must NOT have resurrected any profile-0 credential: not the
     * previously persisted B, and not the just-enrolled C. */
    assert(count_profile(0) == 0);
    /* Profile 1's credential A must have survived. */
    assert(count_profile(1) == 1);
    assert(persisted[0].in_use && persisted[0].profile_id == 1);
    assert(persisted[0].credential_id[0] == 0x0a);

    puts("profile erase/flush host test: ok");
    return 0;
}