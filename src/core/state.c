/*
 * Fjaeger - core state machine.
 */
#include <string.h>

#include "state.h"
#include "crypto.h"
#include "keys.h"
#include "msc_disk.h"
#include "ctap2.h"
#include "pico/time.h"

#define PIN_MIN_LEN 4
#define PIN_MAX_LEN 32

/* SHA-256 of the PIN, loaded from / persisted to the flash store. */
static uint8_t pin_hash[FJ_HASH_LEN];
static bool pin_configured = false;

static fj_state_t state = FJ_STATE_LOCKED;
static uint32_t timeout_sec = FJ_DEFAULT_TIMEOUT_SEC;
static absolute_time_t unlock_since;
static bool have_unlock_time = false;

void fj_state_init(void) {
    state = FJ_STATE_LOCKED;
    pin_configured = fj_keys_get_pin_hash(pin_hash);
    timeout_sec = FJ_DEFAULT_TIMEOUT_SEC;
    (void)fj_keys_get_timeout(&timeout_sec);
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
    /* The device lock is the security boundary for every subsystem. */
    fj_msc_lock();
    state = FJ_STATE_LOCKED;
    have_unlock_time = false;
}

bool fj_state_profile_erase(unsigned profile_id) {
    /* A single consistent operation: purge the live CTAP2 cache first so a
     * deferred flush can never write erased credentials back to flash, then
     * remove the profile and its credentials from the persistent store. */
    fj_ctap2_forget_profile(profile_id);
    return fj_keys_profile_erase(profile_id);
}

bool fj_state_unlock(const char *pin) {
    if (!pin_configured) return false;

    /* Brute-force protection: a blocked PIN requires the PUK. */
    fj_security_t sec;
    if (!fj_keys_get_security(&sec)) return false;
    if (sec.pin_blocked) return false;

    uint8_t hash[FJ_HASH_LEN];
    fj_sha256((const uint8_t *)pin, strlen(pin), hash);

    /* Constant-time comparison to avoid timing leaks. */
    uint8_t acc = 0;
    for (size_t i = 0; i < FJ_HASH_LEN; i++) {
        acc |= hash[i] ^ pin_hash[i];
    }
    if (acc != 0) {
        /* Wrong PIN: count it and block once the limit is reached. */
        sec.pin_fail++;
        if (sec.pin_fail >= FJ_MAX_PIN_FAILS) sec.pin_blocked = 1;
        fj_keys_set_security(&sec);
        return false;
    }

    /* Correct PIN resets the counter. */
    if (sec.pin_fail != 0 || sec.pin_blocked) {
        sec.pin_fail = 0;
        sec.pin_blocked = 0;
        fj_keys_set_security(&sec);
    }

    state = FJ_STATE_UNLOCKED;
    unlock_since = get_absolute_time();
    have_unlock_time = true;
    return true;
}

/* True when the device PIN is currently blocked and needs a PUK. */
bool fj_state_pin_blocked(void) {
    fj_security_t sec;
    return fj_keys_get_security(&sec) && sec.pin_blocked;
}

void fj_state_factory_reset(void) {
    /* Flush and destroy live material before erasing its persistent copy. */
    fj_msc_lock();
    fj_ctap2_forget_all();
    fj_keys_wipe();
    memset(pin_hash, 0, sizeof(pin_hash));
    pin_configured = false;
    state = FJ_STATE_LOCKED;
    have_unlock_time = false;
    timeout_sec = FJ_DEFAULT_TIMEOUT_SEC;
}

fj_puk_result_t fj_state_verify_puk(const char *puk) {
    if (!puk) return FJ_PUK_WRONG;
    uint8_t stored[FJ_HASH_LEN];
    if (!fj_keys_get_puk_hash(stored)) return FJ_PUK_UNSET;

    fj_security_t sec;
    if (!fj_keys_get_security(&sec)) return FJ_PUK_WRONG;

    uint8_t hash[FJ_HASH_LEN];
    fj_sha256((const uint8_t *)puk, strlen(puk), hash);

    uint8_t acc = 0;
    for (size_t i = 0; i < FJ_HASH_LEN; i++) acc |= hash[i] ^ stored[i];
    if (acc != 0) {
        /* Wrong PUK: escalate to a wipe after FJ_MAX_PUK_FAILS. */
        sec.puk_fail++;
        if (sec.puk_fail >= FJ_MAX_PUK_FAILS) {
            fj_state_factory_reset();
            return FJ_PUK_WIPED;
        }
        fj_keys_set_security(&sec);
        return FJ_PUK_WRONG;
    }

    if (sec.puk_fail != 0) {
        sec.puk_fail = 0;
        if (!fj_keys_set_security(&sec)) return FJ_PUK_WRONG;
    }
    return FJ_PUK_OK;
}

fj_puk_result_t fj_state_unlock_puk(const char *puk) {
    fj_puk_result_t result = fj_state_verify_puk(puk);
    if (result != FJ_PUK_OK) return result;

    fj_security_t sec;
    if (!fj_keys_get_security(&sec)) return FJ_PUK_WRONG;

    /* Correct PUK: reset PIN and PUK counters, unblock and unlock. */
    sec.pin_fail = 0;
    sec.pin_blocked = 0;
    if (!fj_keys_set_security(&sec)) return FJ_PUK_WRONG;
    state = FJ_STATE_UNLOCKED;
    unlock_since = get_absolute_time();
    have_unlock_time = true;
    return FJ_PUK_OK;
}

/* Provision (or change) the recovery PUK. Requires the device to be
 * unlocked. Returns true on success. */
bool fj_state_set_puk(const char *puk) {
    size_t len = strlen(puk);
    if (len < 8 || len > 64) return false;
    if (state != FJ_STATE_UNLOCKED) return false;

    uint8_t hash[FJ_HASH_LEN];
    fj_sha256((const uint8_t *)puk, len, hash);
    return fj_keys_set_puk_hash(hash);
}

bool fj_state_set_timeout(uint32_t seconds) {
    if (!fj_keys_set_timeout(seconds)) return false;
    timeout_sec = seconds;
    if (state == FJ_STATE_UNLOCKED && seconds > 0) {
        unlock_since = get_absolute_time();
        have_unlock_time = true;
    } else {
        have_unlock_time = false;
    }
    return true;
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
