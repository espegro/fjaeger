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
static uint8_t stored_puk[32];
static bool have_pin;
static bool have_puk;
static fj_security_t security;
static int64_t now_us;
static unsigned disk_lock_count;
static unsigned ctap_forget_count;
static unsigned wipe_count;
static uint32_t stored_timeout;
static bool have_timeout;

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

bool fj_keys_set_pin_hash(const uint8_t hash[32]) {
    memcpy(stored_pin, hash, 32);
    have_pin = true;
    security.pin_fail = 0;
    security.pin_blocked = 0;
    return true;
}

bool fj_keys_get_pin_hash(uint8_t hash[32]) {
    if (!have_pin) return false;
    memcpy(hash, stored_pin, 32);
    return true;
}

bool fj_keys_get_security(fj_security_t *out) {
    *out = security;
    return true;
}

bool fj_keys_set_security(const fj_security_t *in) {
    security = *in;
    return true;
}

bool fj_keys_set_puk_hash(const uint8_t hash[32]) {
    memcpy(stored_puk, hash, 32);
    have_puk = true;
    security.puk_fail = 0;
    return true;
}

bool fj_keys_get_puk_hash(uint8_t hash[32]) {
    if (!have_puk) return false;
    memcpy(hash, stored_puk, 32);
    return true;
}

void fj_keys_wipe(void) {
    memset(stored_pin, 0, sizeof(stored_pin));
    memset(stored_puk, 0, sizeof(stored_puk));
    memset(&security, 0, sizeof(security));
    have_pin = false;
    have_puk = false;
    have_timeout = false;
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

void fj_msc_lock(void) { disk_lock_count++; }
void fj_ctap2_forget_all(void) { ctap_forget_count++; }

static void reset_fixture(void) {
    memset(stored_pin, 0, sizeof(stored_pin));
    memset(stored_puk, 0, sizeof(stored_puk));
    memset(&security, 0, sizeof(security));
    have_pin = false;
    have_puk = false;
    have_timeout = false;
    now_us = 0;
    disk_lock_count = 0;
    ctap_forget_count = 0;
    wipe_count = 0;
    fj_state_init();
}

static void test_pin_block_and_puk_recovery(void) {
    reset_fixture();
    assert(fj_state_set_pin("12345"));
    assert(fj_state_unlock("12345"));
    assert(fj_state_set_puk("recovery-code"));
    fj_state_lock();

    for (unsigned i = 0; i < FJ_MAX_PIN_FAILS; i++) {
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
        assert(fj_state_verify_puk("wrong-puk") == FJ_PUK_WRONG);
    }
    assert(fj_state_verify_puk("wrong-puk") == FJ_PUK_WIPED);
    assert(wipe_count == 1);
    assert(ctap_forget_count == 1);
    assert(!fj_state_pin_configured());
    assert(fj_state_get() == FJ_STATE_LOCKED);
    assert(fj_state_timeout() == FJ_DEFAULT_TIMEOUT_SEC);
    assert(!have_pin && !have_puk);
}

int main(void) {
    test_pin_block_and_puk_recovery();
    test_auto_lock_closes_disk();
    test_wrong_puk_factory_wipes_live_state();
    puts("security host tests: ok");
    return 0;
}
