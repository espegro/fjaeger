#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "crypto.h"
#include "keys.h"
#include "state.h"
#include "pico/time.h"

static uint8_t stored_pin[32];
static uint8_t stored_pin_salt[16];
static uint8_t stored_ctap2_verifier[16];
static uint8_t stored_puk[32];
static uint8_t stored_puk_salt[16];
static bool have_pin;
static bool have_puk;
static fj_security_t security;
static int64_t now_us;
static unsigned disk_lock_count;
static unsigned ctap_forget_count;
static unsigned wipe_count;
static uint32_t stored_timeout;
static bool have_timeout;
static uint8_t stored_cwk_enc[32];
static uint8_t stored_cwk_salt[16];
static bool have_cwk;

absolute_time_t get_absolute_time(void) { return now_us; }

int64_t absolute_time_diff_us(absolute_time_t from, absolute_time_t to) {
    return to - from;
}

/* A deterministic host-test hash. These tests exercise state transitions,
 * not the production SHA-256 implementation. */
void fj_sha256(const uint8_t *data, size_t len, uint8_t out[32]) {
    memset(out, 0, 32);
    for (size_t i = 0; i < len; i++) {
        out[i % 32] ^= (uint8_t)(data[i] + (uint8_t)i);
    }
}

/* Deterministic RNG so salt generation is reproducible in the test. */
void fj_random(void *buf, size_t len) {
    static uint8_t c = 0x5a;
    uint8_t *p = buf;
    for (size_t i = 0; i < len; i++) p[i] = c++;
}

/* Deterministic PBKDF2 stand-in: consistent for the same (pw, salt), which is
 * all the state machine needs. (The real KDF is tested on the device.) */
bool fj_pbkdf2_sha256(const uint8_t *pw, size_t pw_len, const uint8_t *salt,
                      size_t salt_len, uint32_t iter, uint8_t out[32]) {
    memset(out, 0, 32);
    size_t n = 0;
    for (size_t i = 0; i < pw_len; i++) { out[n % 32] ^= (uint8_t)(pw[i] + i); n++; }
    for (size_t i = 0; i < salt_len; i++) out[(n + i) % 32] ^= (uint8_t)(salt[i] + i);
    out[0] ^= (uint8_t)iter;
    return true;
}

bool fj_keys_set_pin(const uint8_t pbkdf2_hash[32], const uint8_t salt[16],
                     const uint8_t ctap2_verifier[16]) {
    memcpy(stored_pin, pbkdf2_hash, 32);
    memcpy(stored_pin_salt, salt, 16);
    memcpy(stored_ctap2_verifier, ctap2_verifier, 16);
    have_pin = true;
    security.pin_fail = 0;
    security.pin_blocked = 0;
    return true;
}

bool fj_keys_pin_configured(void) { return have_pin; }

void fj_keys_get_pin(uint8_t pbkdf2_hash[32], uint8_t salt[16],
                     uint8_t ctap2_verifier[16]) {
    memcpy(pbkdf2_hash, stored_pin, 32);
    memcpy(salt, stored_pin_salt, 16);
    memcpy(ctap2_verifier, stored_ctap2_verifier, 16);
}
void fj_led_pin_lock(void) {}
void fj_led_pin_unlock(void) {}

bool fj_keys_get_security(fj_security_t *out) {
    *out = security;
    return true;
}

bool fj_keys_set_security(const fj_security_t *in) {
    security = *in;
    return true;
}

bool fj_keys_set_puk(const uint8_t pbkdf2_hash[32], const uint8_t salt[16]) {
    memcpy(stored_puk, pbkdf2_hash, 32);
    memcpy(stored_puk_salt, salt, 16);
    have_puk = true;
    security.puk_fail = 0;
    return true;
}

bool fj_keys_get_puk(uint8_t pbkdf2_hash[32], uint8_t salt[16]) {
    if (!have_puk) return false;
    memcpy(pbkdf2_hash, stored_puk, 32);
    memcpy(salt, stored_puk_salt, 16);
    return true;
}

void fj_keys_wipe(void) {
    memset(stored_pin, 0, sizeof(stored_pin));
    memset(stored_pin_salt, 0, sizeof(stored_pin_salt));
    memset(stored_ctap2_verifier, 0, sizeof(stored_ctap2_verifier));
    memset(stored_puk, 0, sizeof(stored_puk));
    memset(stored_puk_salt, 0, sizeof(stored_puk_salt));
    memset(&security, 0, sizeof(security));
    memset(stored_cwk_enc, 0, sizeof(stored_cwk_enc));
    memset(stored_cwk_salt, 0, sizeof(stored_cwk_salt));
    have_pin = false;
    have_puk = false;
    have_timeout = false;
    have_cwk = false;
    wipe_count++;
}

bool fj_keys_get_timeout(uint32_t *seconds) {
    if (!have_timeout) return false;
    *seconds = stored_timeout;
    return true;
}

bool fj_keys_set_timeout(uint32_t seconds) {
    stored_timeout = seconds;
    have_timeout = true;
    return true;
}

/* Credential wrapping key stubs. */
bool fj_keys_cwk_set(void) { return have_cwk; }

bool fj_keys_set_cwk(const uint8_t enc[32], const uint8_t salt[16]) {
    memcpy(stored_cwk_enc, enc, 32);
    memcpy(stored_cwk_salt, salt, 16);
    have_cwk = true;
    return true;
}

bool fj_keys_get_cwk(uint8_t enc[32], uint8_t salt[16]) {
    if (!have_cwk) return false;
    memcpy(enc, stored_cwk_enc, 32);
    memcpy(salt, stored_cwk_salt, 16);
    return true;
}

void fj_msc_lock(void) { disk_lock_count++; }
void fj_ctap2_forget_all(void) { ctap_forget_count++; }
void fj_ctap2_forget_profile(unsigned profile_id) { (void)profile_id; ctap_forget_count++; }

bool fj_keys_profile_erase(unsigned profile_id) {
    (void)profile_id;
    return true;
}

static void reset_fixture(void) {
    memset(stored_pin, 0, sizeof(stored_pin));
    memset(stored_pin_salt, 0, sizeof(stored_pin_salt));
    memset(stored_ctap2_verifier, 0, sizeof(stored_ctap2_verifier));
    memset(stored_puk, 0, sizeof(stored_puk));
    memset(stored_puk_salt, 0, sizeof(stored_puk_salt));
    memset(&security, 0, sizeof(security));
    memset(stored_cwk_enc, 0, sizeof(stored_cwk_enc));
    memset(stored_cwk_salt, 0, sizeof(stored_cwk_salt));
    have_pin = false;
    have_puk = false;
    have_timeout = false;
    have_cwk = false;
    now_us = 0;
    disk_lock_count = 0;
    ctap_forget_count = 0;
    wipe_count = 0;
    fj_state_brute_success(FJ_BRUTE_PIN);
    fj_state_brute_success(FJ_BRUTE_PUK);
    fj_state_brute_success(FJ_BRUTE_DISK);
    fj_state_init();
}

static void test_pin_block_and_puk_recovery(void) {
    reset_fixture();
    assert(fj_state_set_pin("12345"));
    assert(fj_state_unlock("12345"));
    assert(fj_state_set_puk("recovery-code"));
    fj_state_lock();

    for (unsigned i = 0; i < FJ_MAX_PIN_FAILS; i++) {
        /* The brute-force backoff grows a delay between failed attempts;
         * advance the clock past the cap so each try is actually verified. */
        now_us += 40000000;
        assert(!fj_state_unlock("wrong"));
    }
    assert(fj_state_pin_blocked());
    assert(!fj_state_unlock("12345"));
    assert(fj_state_unlock_puk("recovery-code") == FJ_PUK_OK);
    assert(fj_state_get() == FJ_STATE_UNLOCKED);
    assert(!fj_state_pin_blocked());
    assert(security.pin_fail == 0);
}

static void test_auto_lock_closes_disk(void) {
    reset_fixture();
    assert(fj_state_timeout() == FJ_DEFAULT_TIMEOUT_SEC);
    assert(fj_state_set_pin("12345"));
    assert(fj_state_unlock("12345"));
    assert(fj_state_set_timeout(2));
    fj_state_init();
    assert(fj_state_timeout() == 2);
    assert(fj_state_unlock("12345"));
    unsigned before = disk_lock_count;
    now_us = 1999999;
    fj_state_tick();
    assert(fj_state_get() == FJ_STATE_UNLOCKED);
    now_us = 2000000;
    fj_state_tick();
    assert(fj_state_get() == FJ_STATE_LOCKED);
    assert(disk_lock_count == before + 1);

    assert(fj_state_unlock("12345"));
    assert(fj_state_set_timeout(0));
    fj_state_init();
    assert(fj_state_timeout() == 0);
    assert(fj_state_unlock("12345"));
    now_us += 24LL * 60 * 60 * 1000000;
    fj_state_tick();
    assert(fj_state_get() == FJ_STATE_UNLOCKED);
}

static void test_wrong_puk_factory_wipes_live_state(void) {
    reset_fixture();
    assert(fj_state_set_pin("12345"));
    assert(fj_state_unlock("12345"));
    assert(fj_state_set_puk("recovery-code"));
    fj_state_lock();

    for (unsigned i = 1; i < FJ_MAX_PUK_FAILS; i++) {
        /* Pace the attempts past the brute-force backoff cap. */
        now_us += 40000000;
        assert(fj_state_verify_puk("wrong-puk") == FJ_PUK_WRONG);
    }
    now_us += 40000000;
    assert(fj_state_verify_puk("wrong-puk") == FJ_PUK_WIPED);
    assert(wipe_count == 1);
    assert(ctap_forget_count == 1);
    assert(!fj_state_pin_configured());
    assert(fj_state_get() == FJ_STATE_LOCKED);
    assert(fj_state_timeout() == FJ_DEFAULT_TIMEOUT_SEC);
    assert(!have_pin && !have_puk);
}

static void test_profile_erase_consistent(void) {
    reset_fixture();
    assert(fj_state_set_pin("12345"));
    assert(fj_state_unlock("12345"));

    unsigned before = ctap_forget_count;
    /* Erasing a non-active profile must purge the live CTAP2 cache and the
     * persistent profile store in one operation. */
    assert(fj_state_profile_erase(1));
    assert(ctap_forget_count == before + 1);
}

static void test_brute_force_delay_backoff(void) {
    reset_fixture();
    assert(fj_state_set_pin("12345"));
    assert(fj_state_unlock("12345"));
    fj_state_lock();

    /* Immediately after boot an attempt is allowed. */
    now_us = 0;
    assert(fj_state_brute_ok(FJ_BRUTE_PIN));
    assert(!fj_state_unlock("wrong"));   /* failure 1: 2 s delay */

    /* A second attempt within the delay window is refused outright (before
     * any PBKDF2 work) and does not consume a retry. */
    now_us = 1000000;
    assert(!fj_state_brute_ok(FJ_BRUTE_PIN));
    assert(!fj_state_unlock("wrong"));

    /* After the delay has elapsed a wrong attempt is counted again. */
    now_us = 1999999;
    assert(!fj_state_brute_ok(FJ_BRUTE_PIN));
    now_us = 2000000;
    assert(fj_state_brute_ok(FJ_BRUTE_PIN));
    assert(!fj_state_unlock("wrong"));   /* failure 2: 4 s delay */

    now_us = 5000000;
    assert(!fj_state_brute_ok(FJ_BRUTE_PIN));
    now_us = 6000001;
    assert(fj_state_brute_ok(FJ_BRUTE_PIN));

    /* The PIN delay does not affect a PUK attempt (separate contexts). */
    assert(fj_state_brute_ok(FJ_BRUTE_PUK));

    /* A correct PIN clears the backoff. */
    assert(fj_state_unlock("12345"));
    assert(fj_state_get() == FJ_STATE_UNLOCKED);
    assert(fj_state_brute_ok(FJ_BRUTE_PIN));
}

static void test_cwk_at_rest(void) {
    reset_fixture();

    /* No PIN, no CWK. */
    uint8_t cwk[32];
    assert(!fj_state_cwk(cwk));
    assert(!fj_keys_cwk_set());

    /* Setting a PIN creates and wraps a credential wrapping key. */
    assert(fj_state_set_pin("12345"));
    assert(fj_keys_cwk_set());
    assert(fj_state_cwk(cwk));

    /* The wrapped form stored in flash must differ from the plaintext CWK. */
    uint8_t enc[32], salt[16];
    assert(fj_keys_get_cwk(enc, salt));
    assert(memcmp(enc, cwk, 32) != 0);

    /* Locking wipes the CWK from RAM; the wrapped form remains in flash. */
    fj_state_lock();
    assert(!fj_state_cwk(cwk));
    assert(fj_keys_cwk_set());

    /* Re-entering the PIN recovers the same CWK. */
    assert(fj_state_unlock("12345"));
    uint8_t cwk2[32];
    assert(fj_state_cwk(cwk2));
    assert(memcmp(cwk, cwk2, 32) == 0);

    /* A factory wipe clears the persisted CWK too. */
    fj_state_factory_reset();
    assert(!fj_keys_cwk_set());
    assert(!fj_state_cwk(cwk));
}

int main(void) {
    test_pin_block_and_puk_recovery();
    test_auto_lock_closes_disk();
    test_wrong_puk_factory_wipes_live_state();
    test_profile_erase_consistent();
    test_brute_force_delay_backoff();
    test_cwk_at_rest();
    puts("security host tests: ok");
    return 0;
}
