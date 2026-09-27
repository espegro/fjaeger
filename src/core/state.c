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

/* The unlock passphrase can be longer than a FIDO PIN; it is the primary
 * secret that protects the master key M. */
#define PASS_MIN_LEN 8
#define PASS_MAX_LEN 64

/* PBKDF2-SHA256 of the unlock passphrase (with its salt) loaded from /
 * persisted to the flash store. The passphrase protects the master key M. It
 * is independent of the CTAP2 PIN (which only authenticates the CTAP2 client
 * PIN protocol), so a fast brute-force of the CTAP2 verifier cannot recover
 * the passphrase that unwraps M. */
static uint8_t pass_hash[FJ_HASH_LEN];
static uint8_t pass_salt[FJ_PIN_SALT_LEN];
static bool pass_configured = false;

/* The 16-byte CTAP2 client-PIN verifier (LEFT(SHA-256(pin),16)), independent
 * of the unlock passphrase. Used only by the CTAP2 clientPIN protocol. */
static uint8_t ctap2_pin_verifier[16];
static bool ctap2_pin_configured = false;

/* The master key M, held in RAM only while the device is unlocked. It wraps
 * every CTAP2 credential private key at rest. It can be recovered by either
 * the device PIN or the recovery PUK; it is wiped on lock. */
static uint8_t master[32];
static bool master_available = false;

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
    pass_configured = fj_keys_passphrase_configured();
    if (pass_configured)
        fj_keys_get_passphrase(pass_hash, pass_salt);
    ctap2_pin_configured = fj_keys_ctap2_pin_configured();
    if (ctap2_pin_configured)
        fj_keys_get_ctap2_pin(ctap2_pin_verifier);
    timeout_sec = FJ_DEFAULT_TIMEOUT_SEC;
    (void)fj_keys_get_timeout(&timeout_sec);
    have_unlock_time = false;
    /* The device starts locked, so no master key is available until it is
     * unlocked with the passphrase or PUK. */
    memset(master, 0, sizeof(master));
    master_available = false;
}

fj_state_t fj_state_get(void) {
    return state;
}

bool fj_state_pin_configured(void) {
    return pass_configured;
}

bool fj_state_ctap2_pin_configured(void) {
    return ctap2_pin_configured;
}

/* Unwrap the master key M using a passphrase and one of its stored wrapped
 * forms (PIN or PUK). XOR-wrapped like the disk key. On success M is held in
 * RAM until the device locks. 'salt' is the salt for 'wrap_enc'. */
static bool master_unwrap(const char *secret, size_t len,
                          const uint8_t wrap_enc[32], const uint8_t salt[16]) {
    uint8_t wrap[32];
    if (!fj_pbkdf2_sha256((const uint8_t *)secret, len, salt, 16,
                          FJ_PBKDF2_ITERATIONS, wrap))
        return false;
    for (int i = 0; i < 32; i++) master[i] = wrap_enc[i] ^ wrap[i];
    memset(wrap, 0, sizeof(wrap));
    master_available = true;
    return true;
}

static bool master_unwrap_passphrase(const char *passphrase, size_t len) {
    uint8_t enc[32], salt[16];
    if (!fj_keys_get_master_pin_wrap(enc, salt)) return false;
    return master_unwrap(passphrase, len, enc, salt);
}

static bool master_unwrap_puk(const char *puk, size_t len) {
    uint8_t enc[32], salt[16];
    if (!fj_keys_get_master_puk_wrap(enc, salt)) return false;
    return master_unwrap(puk, len, enc, salt);
}

/* Ensure the master key M exists (generating it on first use) and wrap it
 * with 'secret' using a fresh salt, storing the wrapped form via 'set_wrap'.
 * Used when the PIN or PUK is set or changed. */
static bool master_wrap_with(const char *secret, size_t len,
                             bool (*set_wrap)(const uint8_t[32], const uint8_t[16])) {
    uint8_t enc[32], salt[16];
    if (!fj_keys_master_key_set() && !master_available) {
        /* First master key: fresh random value and salt. */
        fj_random(salt, sizeof(salt));
        fj_random(master, sizeof(master));
        master_available = true;
    } else {
        /* A master key already exists (either in the store or held in RAM,
         * e.g. after a restore); keep it and just re-wrap with a fresh salt. */
        fj_random(salt, sizeof(salt));
    }

    uint8_t wrap[32];
    if (!fj_pbkdf2_sha256((const uint8_t *)secret, len, salt, 16,
                          FJ_PBKDF2_ITERATIONS, wrap))
        return false;
    for (int i = 0; i < 32; i++) enc[i] = master[i] ^ wrap[i];
    memset(wrap, 0, sizeof(wrap));
    if (!set_wrap(enc, salt)) return false;
    master_available = true;
    return true;
}

bool fj_state_set_passphrase(const char *passphrase) {
    size_t len = strlen(passphrase);
    if (len < PASS_MIN_LEN || len > PASS_MAX_LEN) return false;
    /* The initial passphrase can be set on an unconfigured device. Changing
     * an existing passphrase requires the device to have been unlocked first
     * (so the master key is available to re-wrap). */
    if (pass_configured && state != FJ_STATE_UNLOCKED) return false;

    fj_random(pass_salt, FJ_PIN_SALT_LEN);
    if (!fj_pbkdf2_sha256((const uint8_t *)passphrase, len, pass_salt,
                          FJ_PIN_SALT_LEN, FJ_PBKDF2_ITERATIONS, pass_hash))
        return false;

    if (!fj_keys_set_passphrase(pass_hash, pass_salt)) return false;
    pass_configured = true;
    /* Ensure the master key exists and is wrapped by the new passphrase so
     * credential private keys can be encrypted at rest. This is independent
     * of the CTAP2 PIN. */
    if (!master_wrap_with(passphrase, len, fj_keys_set_master_pin_wrap))
        return false;
    return true;
}

/* Set the CTAP2 client PIN (independent of the unlock passphrase). Stored as
 * LEFT(SHA-256(pin),16) for the CTAP2 clientPIN protocol. Requires the device
 * unlocked. Does not touch the master key. */
bool fj_state_set_ctap2_pin(const char *pin) {
    size_t len = strlen(pin);
    if (len < PIN_MIN_LEN || len > PIN_MAX_LEN) return false;
    if (state != FJ_STATE_UNLOCKED) return false;

    uint8_t sha[FJ_HASH_LEN];
    fj_sha256((const uint8_t *)pin, len, sha);
    memcpy(ctap2_pin_verifier, sha, 16);
    if (!fj_keys_set_ctap2_pin(ctap2_pin_verifier)) return false;
    ctap2_pin_configured = true;
    return true;
}

/* Verify the CTAP2 client PIN verifier (LEFT(SHA-256(pin),16)) supplied by
 * the CTAP2 clientPIN protocol. Returns true if it matches the configured
 * CTAP2 PIN. With no CTAP2 PIN set, accepts anything (dummy mode). */
bool fj_state_ctap2_verify(const uint8_t verifier[16]) {
    if (!ctap2_pin_configured) return true;   /* dummy mode */
    uint8_t acc = 0;
    for (int i = 0; i < 16; i++) acc |= ctap2_pin_verifier[i] ^ verifier[i];
    return acc == 0;
}

void fj_state_lock(void) {
    /* The device lock is the security boundary for every subsystem. */
    fj_msc_lock();
    fj_led_pin_lock();
    memset(master, 0, sizeof(master));
    master_available = false;
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

bool fj_state_unlock(const char *passphrase) {
    if (!pass_configured) return false;

    /* Brute-force protection: a blocked passphrase requires the PUK, and a
     * growing delay is imposed between failed attempts. */
    fj_security_t sec;
    if (!fj_keys_get_security(&sec)) return false;
    if (sec.pin_blocked) return false;
    if (!fj_state_brute_ok(FJ_BRUTE_PIN)) return false;

    uint8_t hash[FJ_HASH_LEN];
    if (!fj_pbkdf2_sha256((const uint8_t *)passphrase, strlen(passphrase),
                          pass_salt, FJ_PIN_SALT_LEN,
                          FJ_PBKDF2_ITERATIONS, hash))
        return false;

    /* Constant-time comparison to avoid timing leaks. */
    uint8_t acc = 0;
    for (size_t i = 0; i < FJ_HASH_LEN; i++) {
        acc |= hash[i] ^ pass_hash[i];
    }
    if (acc != 0) {
        /* Wrong passphrase: count it, grow the backoff delay and block once
         * the limit is reached. */
        sec.pin_fail++;
        if (sec.pin_fail >= FJ_MAX_PIN_FAILS) sec.pin_blocked = 1;
        fj_keys_set_security(&sec);
        fj_state_brute_failure(FJ_BRUTE_PIN);
        return false;
    }

    /* Correct passphrase resets the counter and the backoff delay. */
    if (sec.pin_fail != 0 || sec.pin_blocked) {
        sec.pin_fail = 0;
        sec.pin_blocked = 0;
        fj_keys_set_security(&sec);
    }
    fj_state_brute_success(FJ_BRUTE_PIN);

    /* Unwrap the master key from the passphrase so credential private keys
     * can be decrypted for signing. Failure here is not fatal for the lock
     * state itself but means SSH keys cannot be used until an unlock with the
     * master key available. */
    (void)master_unwrap_passphrase(passphrase, strlen(passphrase));

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
    memset(pass_hash, 0, sizeof(pass_hash));
    memset(pass_salt, 0, sizeof(pass_salt));
    memset(ctap2_pin_verifier, 0, sizeof(ctap2_pin_verifier));
    memset(master, 0, sizeof(master));
    master_available = false;
    pass_configured = false;
    ctap2_pin_configured = false;
    state = FJ_STATE_LOCKED;
    have_unlock_time = false;
    timeout_sec = FJ_DEFAULT_TIMEOUT_SEC;
}

bool fj_state_cwk(uint8_t out[32]) {
    if (!master_available) return false;
    memcpy(out, master, 32);
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

    /* Correct PUK: reset PIN and PUK counters, unblock and unlock. Because
     * the master key M is also wrapped by the PUK, a PUK unlock recovers M,
     * so credential keys remain usable and a new PIN can be set without
     * losing them. */
    sec.pin_fail = 0;
    sec.pin_blocked = 0;
    if (!fj_keys_set_security(&sec)) return FJ_PUK_WRONG;
    if (!master_unwrap_puk(puk, strlen(puk))) return FJ_PUK_WRONG;
    /* A PUK recovery resets the PIN lockout, so clear the PIN backoff gate
     * too; the user can immediately set or re-enter a PIN. */
    fj_state_brute_success(FJ_BRUTE_PIN);
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
    if (!fj_keys_set_puk(hash, salt)) return false;
    /* Wrap the master key with the (new) PUK so a PUK recovery can recover
     * the keys. */
    return master_wrap_with(puk, len, fj_keys_set_master_puk_wrap);
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

/* ------------------------------------------------------------------ */
/* Backup / restore                                                    */
/* ------------------------------------------------------------------ */
#define BACKUP_MAGIC    0x464A4255u   /* "FJBU" */
#define BACKUP_VERSION  1u
#define BACKUP_SALT_LEN 16
#define BACKUP_NONCE_LEN 12
#define BACKUP_TAG_LEN  16
/* Header before the ciphertext: magic(4) || version(1) || salt(16) || nonce(12).
 * The AES-GCM tag follows the ciphertext. */
#define BACKUP_HEADER   (4 + 1 + BACKUP_SALT_LEN + BACKUP_NONCE_LEN)
#define BACKUP_TOTAL(payload_sz) (BACKUP_HEADER + (payload_sz) + BACKUP_TAG_LEN)

/* Backup file on the disk: magic(4) || version(1) || salt(16) || nonce(12)
 * || tag(16) || AES-GCM(payload). The key is PBKDF2(password, salt). */
bool fj_state_backup_write(const char *password) {
    if (!password || state != FJ_STATE_UNLOCKED) return false;
    if (!master_available) return false;

    fj_backup_payload_t payload;
    memset(&payload, 0, sizeof(payload));
    if (!fj_keys_backup_fill(&payload)) return false;
    memcpy(payload.master, master, sizeof(payload.master));

    uint8_t salt[BACKUP_SALT_LEN], nonce[BACKUP_NONCE_LEN], key[32];
    fj_random(salt, sizeof(salt));
    fj_random(nonce, sizeof(nonce));
    if (!fj_pbkdf2_sha256((const uint8_t *)password, strlen(password),
                          salt, sizeof(salt), FJ_PBKDF2_ITERATIONS, key))
        return false;

    uint8_t blob[BACKUP_TOTAL(sizeof(payload))];
    uint32_t magic = BACKUP_MAGIC;
    size_t p = 0;
    memcpy(blob + p, &magic, 4); p += 4;
    blob[p++] = BACKUP_VERSION;
    memcpy(blob + p, salt, sizeof(salt)); p += sizeof(salt);
    memcpy(blob + p, nonce, sizeof(nonce)); p += sizeof(nonce);
    uint8_t tag[BACKUP_TAG_LEN];
    if (!fj_aes_gcm_encrypt(key, nonce, (const uint8_t *)&payload, sizeof(payload),
                            blob + p, tag))
        return false;
    memcpy(blob + p + sizeof(payload), tag, sizeof(tag));

    memset(&payload, 0, sizeof(payload));
    memset(key, 0, sizeof(key));

    bool ok = fj_msc_backup_write(blob, sizeof(blob));
    memset(blob, 0, sizeof(blob));
    return ok;
}

bool fj_state_backup_restore(const char *password, const char *new_pass,
                             const char *new_puk) {
    if (!password || !new_pass || !new_puk) return false;
    size_t pass_len = strlen(new_pass), puk_len = strlen(new_puk);
    if (pass_len < PASS_MIN_LEN || pass_len > PASS_MAX_LEN) return false;
    if (puk_len < 8 || puk_len > 64) return false;

    uint8_t blob[BACKUP_TOTAL(sizeof(fj_backup_payload_t))];
    size_t blob_len = 0;
    if (!fj_msc_backup_read(blob, sizeof(blob), &blob_len)) return false;
    if (blob_len != BACKUP_TOTAL(sizeof(fj_backup_payload_t)))
        return false;

    uint32_t magic;
    memcpy(&magic, blob, 4);
    if (magic != BACKUP_MAGIC || blob[4] != BACKUP_VERSION) return false;

    const uint8_t *salt = blob + 5;
    const uint8_t *nonce = blob + 5 + BACKUP_SALT_LEN;
    const uint8_t *cipher = blob + BACKUP_HEADER;
    const uint8_t *tag = cipher + sizeof(fj_backup_payload_t);

    uint8_t key[32];
    if (!fj_pbkdf2_sha256((const uint8_t *)password, strlen(password),
                          salt, BACKUP_SALT_LEN, FJ_PBKDF2_ITERATIONS, key))
        return false;

    fj_backup_payload_t payload;
    if (!fj_aes_gcm_decrypt(key, nonce, tag, cipher, sizeof(payload),
                            (uint8_t *)&payload)) {
        memset(key, 0, sizeof(key));
        return false;
    }
    memset(key, 0, sizeof(key));

    /* Import the store and hold the recovered master key in RAM. */
    if (!fj_keys_backup_restore(&payload)) return false;
    memcpy(master, payload.master, sizeof(master));
    master_available = true;
    memset(&payload, 0, sizeof(payload));
    memset(blob, 0, sizeof(blob));

    /* Set the new unlock passphrase and re-wrap the recovered master key with
     * it. (The CTAP2 PIN is separate and is set with SETPIN afterwards.) */
    fj_random(pass_salt, FJ_PIN_SALT_LEN);
    if (!fj_pbkdf2_sha256((const uint8_t *)new_pass, pass_len, pass_salt,
                          FJ_PIN_SALT_LEN, FJ_PBKDF2_ITERATIONS, pass_hash))
        return false;
    if (!fj_keys_set_passphrase(pass_hash, pass_salt)) return false;
    pass_configured = true;
    if (!master_wrap_with(new_pass, pass_len, fj_keys_set_master_pin_wrap))
        return false;

    /* Set the new recovery PUK and re-wrap the master key with it too. */
    uint8_t puk_salt[FJ_PUK_SALT_LEN], puk_hash[FJ_HASH_LEN];
    fj_random(puk_salt, FJ_PUK_SALT_LEN);
    if (!fj_pbkdf2_sha256((const uint8_t *)new_puk, puk_len, puk_salt,
                          FJ_PUK_SALT_LEN, FJ_PBKDF2_ITERATIONS, puk_hash))
        return false;
    if (!fj_keys_set_puk(puk_hash, puk_salt)) return false;
    if (!master_wrap_with(new_puk, puk_len, fj_keys_set_master_puk_wrap))
        return false;

    /* Reload the live CTAP2 cache so the restored credentials are usable
     * immediately without a reboot. */
    fj_ctap2_forget_all();
    fj_ctap2_init();

    state = FJ_STATE_UNLOCKED;
    unlock_since = get_absolute_time();
    have_unlock_time = true;
    return true;
}
