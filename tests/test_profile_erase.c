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
/* Store the PIN hash so the real state.c unlock path can verify it. */
static uint8_t stored_pin[32];
static bool have_pin = false;
bool fj_keys_set_pin_hash(const uint8_t h[32]) {
    memcpy(stored_pin, h, 32); have_pin = true; return true;
}
bool fj_keys_get_pin_hash(uint8_t h[32]) {
    if (!have_pin) return false;
    memcpy(h, stored_pin, 32); return true;
}
bool fj_keys_get_security(fj_security_t *s) { memset(s, 0, sizeof(*s)); return true; }
bool fj_keys_set_security(const fj_security_t *s) { (void)s; return true; }
bool fj_keys_set_puk_hash(const uint8_t h[32]) { (void)h; return true; }
bool fj_keys_get_puk_hash(uint8_t h[32]) { (void)h; return false; }
void fj_keys_wipe(void) { have_pin = false; memset(stored_pin, 0, sizeof(stored_pin)); }
bool fj_keys_get_timeout(uint32_t *s) { *s = 900; return true; }
bool fj_keys_set_timeout(uint32_t s) { (void)s; return true; }

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
    assert(fj_state_set_pin("12345"));
    assert(fj_state_unlock("12345"));
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