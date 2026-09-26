/*
 * Fjaeger - core state machine.
 */
#include <string.h>

#include "state.h"
#include "crypto.h"
#include "keys.h"
#include "pico/time.h"

#define PIN_MIN_LEN 4
#define PIN_MAX_LEN 32

/* SHA-256 of the PIN, loaded from / persisted to the flash store. */
static uint8_t pin_hash[FJ_HASH_LEN];
static bool pin_configured = false;

static fj_state_t state = FJ_STATE_LOCKED;
static uint32_t timeout_sec = 0;
static absolute_time_t unlock_since;
static bool have_unlock_time = false;

void fj_state_init(void) {
    state = FJ_STATE_LOCKED;
    pin_configured = fj_keys_get_pin_hash(pin_hash);
    have_unlock_time = false;
}

fj_state_t fj_state_get(void) {
    return state;
}

bool fj_state_pin_configured(void) {
    return pin_configured;
}

bool fj_state_set_pin(const char *pin) {
    size_t len = strlen(pin);
    if (len < PIN_MIN_LEN || len > PIN_MAX_LEN) return false;
    /* The initial PIN can be set on an unconfigured device. Changing an
     * existing PIN requires the old PIN to have unlocked the device first. */
    if (pin_configured && state != FJ_STATE_UNLOCKED) return false;

    fj_sha256((const uint8_t *)pin, len, pin_hash);
    if (!fj_keys_set_pin_hash(pin_hash)) return false;
    pin_configured = true;
    return true;
}

void fj_state_lock(void) {
    state = FJ_STATE_LOCKED;
    have_unlock_time = false;
}

bool fj_state_unlock(const char *pin) {
    if (!pin_configured) return false;

    uint8_t hash[FJ_HASH_LEN];
    fj_sha256((const uint8_t *)pin, strlen(pin), hash);

    /* Constant-time comparison to avoid timing leaks. */
    uint8_t acc = 0;
    for (size_t i = 0; i < FJ_HASH_LEN; i++) {
        acc |= hash[i] ^ pin_hash[i];
    }
    if (acc != 0) return false;

    state = FJ_STATE_UNLOCKED;
    unlock_since = get_absolute_time();
    have_unlock_time = true;
    return true;
}

void fj_state_set_timeout(uint32_t seconds) {
    timeout_sec = seconds;
    if (state == FJ_STATE_UNLOCKED && seconds > 0) {
        unlock_since = get_absolute_time();
        have_unlock_time = true;
    } else {
        have_unlock_time = false;
    }
}

uint32_t fj_state_timeout(void) {
    return timeout_sec;
}

void fj_state_tick(void) {
    if (state != FJ_STATE_UNLOCKED) return;
    if (timeout_sec == 0 || !have_unlock_time) return;

    if (absolute_time_diff_us(unlock_since, get_absolute_time()) >=
        (int64_t)timeout_sec * 1000000) {
        fj_state_lock();
    }
}
