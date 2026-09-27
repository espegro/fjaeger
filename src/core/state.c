/*
 * Fjaeger - core state machine.
 */
#include <string.h>

#include "state.h"
#include "crypto.h"
#include "keys.h"
#include "msc_disk.h"
#include "ctap2.h"
#include "rgb_led.h"
#include "pico/time.h"

#define PIN_MIN_LEN 4
#define PIN_MAX_LEN 32

/* PBKDF2-SHA256 of the PIN (with its salt) loaded from / persisted to the
 * flash store, plus the 16-byte CTAP2 client-PIN verifier. */
static uint8_t pin_hash[FJ_HASH_LEN];
static uint8_t pin_salt[FJ_PIN_SALT_LEN];
static uint8_t pin_ctap2_verifier[16];
static bool pin_configured = false;

/* The credential wrapping key (CWK), held in RAM only while the device is
 * unlocked by entering the device PIN. It wraps every CTAP2 credential
 * private key at rest. It is wiped on lock. */
static uint8_t cwk[32];
static bool cwk_available = false;

static fj_state_t state = FJ_STATE_LOCKED;
static uint32_t timeout_sec = FJ_DEFAULT_TIMEOUT_SEC;
static absolute_time_t unlock_since;
static bool have_unlock_time = false;

/* Brute-force delay gate: exponential backoff on failed attempts, tracked
 * independently for the PIN, PUK and disk PIN. The delay is RAM-only and
 * based on the monotonic microsecond counter, so it cannot be reset by a
 * reboot, but never persists beyond power-off. */
#define BRUTE_BASE_DELAY_US 2000000u   /* 2 s after the first failure */
#define BRUTE_MAX_DELAY_US  30000000u  /* 30 s cap */
#define BRUTE_CTX_COUNT 3
static uint32_t brute_fail_count[BRUTE_CTX_COUNT];
static absolute_time_t brute_allowed_at[BRUTE_CTX_COUNT];

static fj_brute_ctx_t brute_ctx_index(fj_brute_ctx_t ctx) {
    if (ctx == FJ_BRUTE_PIN) return FJ_BRUTE_PIN;
    if (ctx == FJ_BRUTE_PUK) return FJ_BRUTE_PUK;
    return FJ_BRUTE_DISK;
}

void fj_state_init(void) {
    state = FJ_STATE_LOCKED;
    pin_configured = fj_keys_pin_configured();
    if (pin_configured)
        fj_keys_get_pin(pin_hash, pin_salt, pin_ctap2_verifier);
    timeout_sec = FJ_DEFAULT_TIMEOUT_SEC;
    (void)fj_keys_get_timeout(&timeout_sec);
    have_unlock_time = false;
    /* The device starts locked, so no credential wrapping key is available
     * until the device PIN is entered. */
    memset(cwk, 0, sizeof(cwk));
    cwk_available = false;
}

fj_state_t fj_state_get(void) {
    return state;
}

bool fj_state_pin_configured(void) {
    return pin_configured;
}

/* Unwrap the credential wrapping key (CWK) using PBKDF2(device PIN,
 * cwk_salt), XOR-wrapped like the disk key. The CWK stays in RAM for as long
 * as the device is unlocked. Returns true on success. */
static bool cwk_unwrap(const char *pin, size_t len) {
    uint8_t enc[32], salt[FJ_PIN_SALT_LEN];
    if (!fj_keys_get_cwk(enc, salt)) return false;

    uint8_t wrap[32];
    if (!fj_pbkdf2_sha256((const uint8_t *)pin, len, salt, FJ_PIN_SALT_LEN,
                          FJ_PBKDF2_ITERATIONS, wrap))
        return false;

    for (int i = 0; i < 32; i++) cwk[i] = enc[i] ^ wrap[i];
    cwk_available = true;
    memset(wrap, 0, sizeof(wrap));
    return true;
}

/* Ensure a CWK exists and is wrapped by the given PIN. On first use it
 * generates a fresh random CWK and salt. Used when the PIN is set or
 * changed. */
static bool cwk_ensure_wrapped(const char *pin, size_t len) {
    uint8_t enc[32], salt[FJ_PIN_SALT_LEN];
    if (!fj_keys_cwk_set()) {
        /* First credential-wrapping key: fresh random value and salt. */
        fj_random(salt, sizeof(salt));
        fj_random(cwk, sizeof(cwk));
    } else if (!fj_keys_get_cwk(enc, salt)) {
        return false;
    }

    uint8_t wrap[32];
    if (!fj_pbkdf2_sha256((const uint8_t *)pin, len, salt, FJ_PIN_SALT_LEN,
                          FJ_PBKDF2_ITERATIONS, wrap))
        return false;

    for (int i = 0; i < 32; i++) enc[i] = cwk[i] ^ wrap[i];
    memset(wrap, 0, sizeof(wrap));
    if (!fj_keys_set_cwk(enc, salt)) return false;
    cwk_available = true;
    return true;
}

bool fj_state_set_pin(const char *pin) {
    size_t len = strlen(pin);
    if (len < PIN_MIN_LEN || len > PIN_MAX_LEN) return false;
    /* The initial PIN can be set on an unconfigured device. Changing an
     * existing PIN requires the old PIN to have unlocked the device first. */
    if (pin_configured && state != FJ_STATE_UNLOCKED) return false;

    fj_random(pin_salt, FJ_PIN_SALT_LEN);
    if (!fj_pbkdf2_sha256((const uint8_t *)pin, len, pin_salt, FJ_PIN_SALT_LEN,
                          FJ_PBKDF2_ITERATIONS, pin_hash))
        return false;
    /* The CTAP2 client-PIN protocol only transmits LEFT(SHA-256(pin),16), so
     * keep a small verifier for it in addition to the PBKDF2 hash. */
    uint8_t sha[FJ_HASH_LEN];
    fj_sha256((const uint8_t *)pin, len, sha);
    memcpy(pin_ctap2_verifier, sha, 16);

    if (!fj_keys_set_pin(pin_hash, pin_salt, pin_ctap2_verifier)) return false;
    pin_configured = true;
    /* Ensure the credential wrapping key is available and wrapped by the new
     * PIN so credential private keys can be encrypted at rest. */
    if (!cwk_ensure_wrapped(pin, len)) return false;
    return true;
}

void fj_state_lock(void) {
    /* The device lock is the security boundary for every subsystem. */
    fj_msc_lock();
    fj_led_pin_lock();
    memset(cwk, 0, sizeof(cwk));
    cwk_available = false;
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

    /* Brute-force protection: a blocked PIN requires the PUK, and a growing
     * delay is imposed between failed attempts. */
    fj_security_t sec;
    if (!fj_keys_get_security(&sec)) return false;
    if (sec.pin_blocked) return false;
    if (!fj_state_brute_ok(FJ_BRUTE_PIN)) return false;

    uint8_t hash[FJ_HASH_LEN];
    if (!fj_pbkdf2_sha256((const uint8_t *)pin, strlen(pin), pin_salt,
                          FJ_PIN_SALT_LEN, FJ_PBKDF2_ITERATIONS, hash))
        return false;

    /* Constant-time comparison to avoid timing leaks. */
    uint8_t acc = 0;
    for (size_t i = 0; i < FJ_HASH_LEN; i++) {
        acc |= hash[i] ^ pin_hash[i];
    }
    if (acc != 0) {
        /* Wrong PIN: count it, grow the backoff delay and block once the
         * limit is reached. */
        sec.pin_fail++;
        if (sec.pin_fail >= FJ_MAX_PIN_FAILS) sec.pin_blocked = 1;
        fj_keys_set_security(&sec);
        fj_state_brute_failure(FJ_BRUTE_PIN);
        return false;
    }

    /* Correct PIN resets the counter and the backoff delay. */
    if (sec.pin_fail != 0 || sec.pin_blocked) {
        sec.pin_fail = 0;
        sec.pin_blocked = 0;
        fj_keys_set_security(&sec);
    }
    fj_state_brute_success(FJ_BRUTE_PIN);

    /* Derive the credential wrapping key from the PIN so credential private
     * keys can be decrypted for signing. Failure here is not fatal for the
     * lock state itself but means SSH keys cannot be used until a PIN unlock
     * with the CWK available. */
    (void)cwk_unwrap(pin, strlen(pin));

    state = FJ_STATE_UNLOCKED;
    unlock_since = get_absolute_time();
    have_unlock_time = true;
    fj_led_pin_unlock();
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
    memset(pin_salt, 0, sizeof(pin_salt));
    memset(pin_ctap2_verifier, 0, sizeof(pin_ctap2_verifier));
    memset(cwk, 0, sizeof(cwk));
    cwk_available = false;
    pin_configured = false;
    state = FJ_STATE_LOCKED;
    have_unlock_time = false;
    timeout_sec = FJ_DEFAULT_TIMEOUT_SEC;
}

bool fj_state_cwk(uint8_t out[32]) {
    if (!cwk_available) return false;
    memcpy(out, cwk, 32);
    return true;
}

fj_puk_result_t fj_state_verify_puk(const char *puk) {
    if (!puk) return FJ_PUK_WRONG;
    uint8_t stored[FJ_HASH_LEN], salt[FJ_PUK_SALT_LEN];
    if (!fj_keys_get_puk(stored, salt)) return FJ_PUK_UNSET;

    fj_security_t sec;
    if (!fj_keys_get_security(&sec)) return FJ_PUK_WRONG;
    if (!fj_state_brute_ok(FJ_BRUTE_PUK)) return FJ_PUK_WRONG;

    uint8_t hash[FJ_HASH_LEN];
    if (!fj_pbkdf2_sha256((const uint8_t *)puk, strlen(puk), salt,
                          FJ_PUK_SALT_LEN, FJ_PBKDF2_ITERATIONS, hash))
        return FJ_PUK_WRONG;

    uint8_t acc = 0;
    for (size_t i = 0; i < FJ_HASH_LEN; i++) acc |= hash[i] ^ stored[i];
    if (acc != 0) {
        /* Wrong PUK: escalate to a wipe after FJ_MAX_PUK_FAILS. */
        sec.puk_fail++;
        fj_state_brute_failure(FJ_BRUTE_PUK);
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
    fj_state_brute_success(FJ_BRUTE_PUK);
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
    fj_led_pin_unlock();
    return FJ_PUK_OK;
}

/* Provision (or change) the recovery PUK. Requires the device to be
 * unlocked. Returns true on success. */
bool fj_state_set_puk(const char *puk) {
    size_t len = strlen(puk);
    if (len < 8 || len > 64) return false;
    if (state != FJ_STATE_UNLOCKED) return false;

    uint8_t salt[FJ_PUK_SALT_LEN], hash[FJ_HASH_LEN];
    fj_random(salt, FJ_PUK_SALT_LEN);
    if (!fj_pbkdf2_sha256((const uint8_t *)puk, len, salt, FJ_PUK_SALT_LEN,
                          FJ_PBKDF2_ITERATIONS, hash))
        return false;
    return fj_keys_set_puk(hash, salt);
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

/* A passphrase attempt is permitted only when any previous backoff delay has
 * elapsed. */
bool fj_state_brute_ok(fj_brute_ctx_t ctx) {
    int c = brute_ctx_index(ctx);
    return absolute_time_diff_us(brute_allowed_at[c], get_absolute_time()) >= 0;
}

/* Record a failed attempt and grow the delay exponentially up to a cap. */
void fj_state_brute_failure(fj_brute_ctx_t ctx) {
    int c = brute_ctx_index(ctx);
    brute_fail_count[c]++;
    uint32_t delay = BRUTE_BASE_DELAY_US;
    for (uint32_t i = 1; i < brute_fail_count[c] && delay < BRUTE_MAX_DELAY_US; i++) {
        if (delay > BRUTE_MAX_DELAY_US / 2) { delay = BRUTE_MAX_DELAY_US; break; }
        delay *= 2;
    }
    if (delay > BRUTE_MAX_DELAY_US) delay = BRUTE_MAX_DELAY_US;
    brute_allowed_at[c] = get_absolute_time() + (absolute_time_t)delay;
}

/* A correct passphrase clears the accumulated backoff for its context. */
void fj_state_brute_success(fj_brute_ctx_t ctx) {
    int c = brute_ctx_index(ctx);
    brute_fail_count[c] = 0;
    brute_allowed_at[c] = 0;
}
