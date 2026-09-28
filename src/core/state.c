/*
 * Fjaeger - core state machine.
 */
#include <string.h>

#include "state.h"
#include "crypto.h"
#include "keys.h"
#include "job.h"
#include "msc_disk.h"
#include "ctap2.h"
#include "pin.h"
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

/* Cooperative (resumable) job API, implemented at the end of this file. The
 * firmware console drives these piecewise from the main loop so USB is
 * serviced between KDF chunks; the synchronous public functions below run the
 * same jobs to completion (used by host tests and non-USB callers). */
void fj_state_job_start(fj_state_job_t *j, fj_job_kind_t kind,
                        const char *a1, const char *a2, const char *a3);
bool fj_state_job_step(fj_state_job_t *j);

/* Shared job buffer for the synchronous API (not re-entrant). */
static fj_state_job_t sync_job;

static bool state_job_sync(fj_state_job_t *j) {
    while (j->busy) fj_state_job_step(j);
    return j->result == FJ_RES_OK;
}


bool fj_state_set_passphrase(const char *passphrase) {
    /* The initial passphrase can be set on an unconfigured device. Changing
     * an existing passphrase requires the device to have been unlocked first
     * (so the master key is available to re-wrap). */
    fj_state_job_start(&sync_job, FJ_JOB_SETPASS, passphrase, NULL, NULL);
    return state_job_sync(&sync_job);
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
    /* A lock is a complete security-session boundary: invalidate the CTAP2
     * pinUvAuthToken and any in-progress resident-discovery/credential-
     * management cursors so no stale state can be reused across a lock
     * (FJ-008). */
    fj_pin_reset_token();
    fj_ctap2_invalidate_discovery();
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
    fj_state_job_start(&sync_job, FJ_JOB_UNLOCK, passphrase, NULL, NULL);
    return state_job_sync(&sync_job);
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
    fj_state_job_start(&sync_job, FJ_JOB_VERIFY_PUK, puk, NULL, NULL);
    state_job_sync(&sync_job);
    switch (sync_job.result) {
        case FJ_RES_OK:     return FJ_PUK_OK;
        case FJ_RES_NO_PUK: return FJ_PUK_UNSET;
        case FJ_RES_WIPED:  return FJ_PUK_WIPED;
        default:            return FJ_PUK_WRONG;
    }
}

fj_puk_result_t fj_state_unlock_puk(const char *puk) {
    fj_state_job_start(&sync_job, FJ_JOB_UNLOCKPUK, puk, NULL, NULL);
    state_job_sync(&sync_job);
    switch (sync_job.result) {
        case FJ_RES_OK:     return FJ_PUK_OK;
        case FJ_RES_NO_PUK: return FJ_PUK_UNSET;
        case FJ_RES_WIPED:  return FJ_PUK_WIPED;
        default:            return FJ_PUK_WRONG;
    }
}

/* Provision (or change) the recovery PUK. Requires the device to be
 * unlocked. Returns true on success. */
bool fj_state_set_puk(const char *puk) {
    fj_state_job_start(&sync_job, FJ_JOB_SETPUK, puk, NULL, NULL);
    return state_job_sync(&sync_job);
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
    fj_state_job_start(&sync_job, FJ_JOB_BACKUP, password, NULL, NULL);
    return state_job_sync(&sync_job);
}

bool fj_state_backup_restore(const char *password, const char *new_pass,
                             const char *new_puk) {
    fj_state_job_start(&sync_job, FJ_JOB_RESTORE, password, new_pass, new_puk);
    return state_job_sync(&sync_job);
}

/* ------------------------------------------------------------------ */
/* Cooperative job implementations                                     */
/*                                                                     */
/* Each job owns resumable fj_kdf contexts and advances a bounded amount
 * of PBKDF2 per fj_state_job_step() call. The firmware console pulls the
 * job from the main loop, so the normal top-of-loop tud_task() keeps USB
 * alive during the multi-second derivations. Finalisation (flash A/B
 * commit) happens entirely within one step so the store is never held open
 * across ticks.                                                    */
/* ------------------------------------------------------------------ */

/* Advance the current KDF by one bounded chunk. Returns true once the
 * derivation has finished. */
static bool kdf_chunk_done(fj_kdf_t *k) {
    unsigned n = 0;
    while (k->running && n++ < FJ_JOB_KDF_CHUNK) fj_kdf_step(k);
    return !k->running;
}

static bool job_begin_kdf(fj_state_job_t *j, unsigned slot,
                          const char *secret, const uint8_t salt[16]) {
    return fj_kdf_begin(&j->kdf[slot], (const uint8_t *)secret,
                        strlen(secret), salt, 16, FJ_PBKDF2_ITERATIONS);
}

/* SETPASS ----------------------------------------------------------------- */
static void job_start_setpass(fj_state_job_t *j, const char *a1) {
    size_t len = strlen(a1);
    if (len < PASS_MIN_LEN || len > PASS_MAX_LEN) { j->result = FJ_RES_BAD_SECRET; j->busy = false; return; }
    if (pass_configured && state != FJ_STATE_UNLOCKED) { j->result = FJ_RES_BAD_SECRET; j->busy = false; return; }
    fj_random(j->salt[0], 16);
    fj_random(j->salt[1], 16);
    if (!fj_keys_master_key_set() && !master_available) {
        fj_random(master, sizeof(master));
        master_available = true;
    }
    if (!job_begin_kdf(j, 0, a1, j->salt[0])) { j->result = FJ_RES_ERR; j->busy = false; return; }
    j->phase = 0;
}

static void job_run_setpass(fj_state_job_t *j) {
    if (j->phase == 0) {
        if (!kdf_chunk_done(&j->kdf[0])) return;
        if (!job_begin_kdf(j, 1, j->a1, j->salt[1])) { j->result = FJ_RES_ERR; j->busy = false; return; }
        j->phase = 1;
        return;
    }
    if (!kdf_chunk_done(&j->kdf[1])) return;
    uint8_t enc[32];
    for (int i = 0; i < 32; i++) enc[i] = master[i] ^ j->kdf[1].out[i];
    fj_store_begin();
    if (!fj_keys_set_passphrase(j->kdf[0].out, j->salt[0])) { fj_store_abort(); j->result = FJ_RES_ERR; j->busy = false; return; }
    pass_configured = true;
    memcpy(pass_hash, j->kdf[0].out, 32);
    memcpy(pass_salt, j->salt[0], 16);
    if (!fj_keys_set_master_pin_wrap(enc, j->salt[1])) { fj_store_abort(); j->result = FJ_RES_ERR; j->busy = false; return; }
    j->result = fj_store_commit() ? FJ_RES_OK : FJ_RES_ERR;
    j->busy = false;
}

/* UNLOCK ------------------------------------------------------------------ */
static void job_start_unlock(fj_state_job_t *j, const char *a1) {
    if (!pass_configured) { j->result = FJ_RES_BAD_PIN; j->busy = false; return; }
    fj_security_t sec;
    if (!fj_keys_get_security(&sec)) { j->result = FJ_RES_ERR; j->busy = false; return; }
    if (sec.pin_blocked) { j->result = FJ_RES_BLOCKED; j->busy = false; return; }
    if (!fj_state_brute_ok(FJ_BRUTE_PIN)) { j->result = FJ_RES_BAD_PIN; j->busy = false; return; }
    if (!job_begin_kdf(j, 0, a1, pass_salt)) { j->result = FJ_RES_ERR; j->busy = false; return; }
    j->phase = 0;
}

static void job_run_unlock(fj_state_job_t *j) {
    if (j->phase == 0) {
        if (!kdf_chunk_done(&j->kdf[0])) return;
        uint8_t acc = 0;
        for (int i = 0; i < 32; i++) acc |= j->kdf[0].out[i] ^ pass_hash[i];
        if (acc) {
            fj_security_t sec;
            if (fj_keys_get_security(&sec)) {
                sec.pin_fail++;
                if (sec.pin_fail >= FJ_MAX_PIN_FAILS) sec.pin_blocked = 1;
                fj_keys_set_security(&sec);
            }
            fj_state_brute_failure(FJ_BRUTE_PIN);
            j->result = FJ_RES_BAD_PIN;
            j->busy = false;
            return;
        }
        fj_security_t sec;
        if (fj_keys_get_security(&sec)) {
            if (sec.pin_fail != 0 || sec.pin_blocked) {
                sec.pin_fail = 0; sec.pin_blocked = 0;
                fj_keys_set_security(&sec);
            }
        }
        fj_state_brute_success(FJ_BRUTE_PIN);
        if (!fj_keys_get_master_pin_wrap(j->enc[1], j->salt[1])) { j->result = FJ_RES_ERR; j->busy = false; return; }
        if (!job_begin_kdf(j, 1, j->a1, j->salt[1])) { j->result = FJ_RES_ERR; j->busy = false; return; }
        j->phase = 1;
        return;
    }
    if (!kdf_chunk_done(&j->kdf[1])) return;
    for (int i = 0; i < 32; i++) master[i] = j->enc[1][i] ^ j->kdf[1].out[i];
    master_available = true;
    state = FJ_STATE_UNLOCKED;
    unlock_since = get_absolute_time();
    have_unlock_time = true;
    fj_led_pin_unlock();
    j->result = FJ_RES_OK;
    j->busy = false;
}

/* SETPUK ------------------------------------------------------------------ */
static void job_start_setpuk(fj_state_job_t *j, const char *a1) {
    size_t len = strlen(a1);
    if (len < 8 || len > 64) { j->result = FJ_RES_BAD_SECRET; j->busy = false; return; }
    if (state != FJ_STATE_UNLOCKED) { j->result = FJ_RES_BAD_SECRET; j->busy = false; return; }
    fj_random(j->salt[0], 16);
    fj_random(j->salt[1], 16);
    if (!job_begin_kdf(j, 0, a1, j->salt[0])) { j->result = FJ_RES_ERR; j->busy = false; return; }
    j->phase = 0;
}

static void job_run_setpuk(fj_state_job_t *j) {
    if (j->phase == 0) {
        if (!kdf_chunk_done(&j->kdf[0])) return;
        if (!job_begin_kdf(j, 1, j->a1, j->salt[1])) { j->result = FJ_RES_ERR; j->busy = false; return; }
        j->phase = 1;
        return;
    }
    if (!kdf_chunk_done(&j->kdf[1])) return;
    uint8_t enc[32];
    for (int i = 0; i < 32; i++) enc[i] = master[i] ^ j->kdf[1].out[i];
    fj_store_begin();
    if (!fj_keys_set_puk(j->kdf[0].out, j->salt[0])) { fj_store_abort(); j->result = FJ_RES_ERR; j->busy = false; return; }
    if (!fj_keys_set_master_puk_wrap(enc, j->salt[1])) { fj_store_abort(); j->result = FJ_RES_ERR; j->busy = false; return; }
    j->result = fj_store_commit() ? FJ_RES_OK : FJ_RES_ERR;
    j->busy = false;
}

/* PUK verification shared by UNLOCKPUK and VERIFY_PUK. After deriving the
 * candidate over the stored salt it applies brute-force accounting (a fifth
 * wrong PUK triggers a factory wipe). Returns true if the PUK was correct. */
static bool puk_apply_verify(fj_state_job_t *j) {
    uint8_t acc = 0;
    for (int i = 0; i < 32; i++) acc |= j->kdf[0].out[i] ^ j->out[0][i];
    if (acc) {
        fj_security_t sec;
        if (!fj_keys_get_security(&sec)) { j->result = FJ_RES_ERR; j->busy = false; return false; }
        sec.puk_fail++;
        fj_state_brute_failure(FJ_BRUTE_PUK);
        if (sec.puk_fail >= FJ_MAX_PUK_FAILS) {
            fj_state_factory_reset();
            j->result = FJ_RES_WIPED;
        } else {
            if (!fj_keys_set_security(&sec)) { j->result = FJ_RES_ERR; } else { j->result = FJ_RES_WRONG_PUK; }
        }
        j->busy = false;
        return false;
    }
    fj_security_t sec;
    if (fj_keys_get_security(&sec) && sec.puk_fail != 0) {
        sec.puk_fail = 0;
        fj_keys_set_security(&sec);
    }
    fj_state_brute_success(FJ_BRUTE_PUK);
    return true;
}

static void job_start_puk_verify(fj_state_job_t *j, const char *a1) {
    if (!fj_keys_puk_configured()) { j->result = FJ_RES_NO_PUK; j->busy = false; return; }
    if (!fj_state_brute_ok(FJ_BRUTE_PUK)) { j->result = FJ_RES_WRONG_PUK; j->busy = false; return; }
    if (!fj_keys_get_puk(j->out[0], j->salt[0])) { j->result = FJ_RES_ERR; j->busy = false; return; }
    if (!job_begin_kdf(j, 0, a1, j->salt[0])) { j->result = FJ_RES_ERR; j->busy = false; return; }
    j->phase = 0;
}

/* Handles FJ_JOB_UNLOCKPUK and FJ_JOB_VERIFY_PUK. */
static void job_run_puk(fj_state_job_t *j) {
    if (j->phase == 0) {
        if (!kdf_chunk_done(&j->kdf[0])) return;
        if (!puk_apply_verify(j)) return;
        if (j->kind == FJ_JOB_VERIFY_PUK) {
            j->result = FJ_RES_OK;
            j->busy = false;
            return;
        }
        /* UNLOCKPUK: recover the master key with the PUK. */
        if (!fj_keys_get_master_puk_wrap(j->enc[1], j->salt[1])) { j->result = FJ_RES_ERR; j->busy = false; return; }
        if (!job_begin_kdf(j, 1, j->a1, j->salt[1])) { j->result = FJ_RES_ERR; j->busy = false; return; }
        j->phase = 1;
        return;
    }
    if (!kdf_chunk_done(&j->kdf[1])) return;
    for (int i = 0; i < 32; i++) master[i] = j->enc[1][i] ^ j->kdf[1].out[i];
    master_available = true;
    fj_security_t sec;
    if (fj_keys_get_security(&sec)) {
        sec.pin_fail = 0; sec.pin_blocked = 0;
        fj_keys_set_security(&sec);
    }
    fj_state_brute_success(FJ_BRUTE_PIN);
    state = FJ_STATE_UNLOCKED;
    unlock_since = get_absolute_time();
    have_unlock_time = true;
    fj_led_pin_unlock();
    j->result = FJ_RES_OK;
    j->busy = false;
}

/* BACKUP ------------------------------------------------------------------ */
static void job_start_backup(fj_state_job_t *j, const char *a1) {
    size_t len = strlen(a1);
    if (state != FJ_STATE_UNLOCKED || !master_available) { j->result = FJ_RES_BAD_SECRET; j->busy = false; return; }
    if (len < 8 || len > 64) { j->result = FJ_RES_BAD_SECRET; j->busy = false; return; }
    if (!fj_msc_is_ready()) { j->result = FJ_RES_DRIVE; j->busy = false; return; }
    fj_random(j->salt[0], 16);
    fj_random(j->nonce[0], 12);
    if (!job_begin_kdf(j, 0, a1, j->salt[0])) { j->result = FJ_RES_ERR; j->busy = false; return; }
    j->phase = 0;
}

static void job_run_backup(fj_state_job_t *j) {
    if (j->phase != 0 || !kdf_chunk_done(&j->kdf[0])) return;
    memset(&j->payload, 0, sizeof(j->payload));
    if (!fj_keys_backup_fill(&j->payload)) { j->result = FJ_RES_ERR; j->busy = false; return; }
    memcpy(j->payload.master, master, sizeof(master));

    size_t p = 0;
    uint32_t magic = BACKUP_MAGIC;
    memcpy(j->blob + p, &magic, 4); p += 4;
    j->blob[p++] = (uint8_t)BACKUP_VERSION;
    memcpy(j->blob + p, j->salt[0], BACKUP_SALT_LEN); p += BACKUP_SALT_LEN;
    memcpy(j->blob + p, j->nonce[0], BACKUP_NONCE_LEN); p += BACKUP_NONCE_LEN;

    uint8_t tag[BACKUP_TAG_LEN];
    if (!fj_aes_gcm_encrypt(j->kdf[0].out, j->nonce[0],
                            (const uint8_t *)&j->payload, sizeof(j->payload),
                            j->blob + p, tag)) { j->result = FJ_RES_ERR; j->busy = false; return; }
    memcpy(j->blob + p + sizeof(j->payload), tag, BACKUP_TAG_LEN);

    j->result = fj_msc_backup_write(j->blob, BACKUP_TOTAL(sizeof(j->payload)))
                ? FJ_RES_OK : FJ_RES_ERR;
    j->busy = false;
}

/* RESTORE ----------------------------------------------------------------- */
static void job_start_restore(fj_state_job_t *j, const char *a1, const char *a2,
                              const char *a3) {
    size_t pw = strlen(a1), np = strlen(a2), npr = strlen(a3);
    if (pw < 8 || pw > 64 || np < PASS_MIN_LEN || np > PASS_MAX_LEN ||
        npr < 8 || npr > 64) { j->result = FJ_RES_BAD_SECRET; j->busy = false; return; }
    if (!fj_msc_is_ready()) { j->result = FJ_RES_DRIVE; j->busy = false; return; }
    if (!fj_msc_backup_read(j->blob, sizeof(j->blob), &j->blob_len)) { j->result = FJ_RES_ERR; j->busy = false; return; }
    if (j->blob_len != BACKUP_TOTAL(sizeof(fj_backup_payload_t))) { j->result = FJ_RES_ERR; j->busy = false; return; }
    uint32_t magic;
    memcpy(&magic, j->blob, 4);
    if (magic != BACKUP_MAGIC || j->blob[4] != (uint8_t)BACKUP_VERSION) { j->result = FJ_RES_ERR; j->busy = false; return; }
    memcpy(j->salt[0], j->blob + 5, BACKUP_SALT_LEN);
    memcpy(j->nonce[0], j->blob + 5 + BACKUP_SALT_LEN, BACKUP_NONCE_LEN);
    if (!job_begin_kdf(j, 0, a1, j->salt[0])) { j->result = FJ_RES_ERR; j->busy = false; return; }
    j->phase = 0;
}

static void job_run_restore(fj_state_job_t *j) {
    switch (j->phase) {
    case 0:
        if (!kdf_chunk_done(&j->kdf[0])) return;
        if (!fj_aes_gcm_decrypt(j->kdf[0].out, j->nonce[0],
                                j->blob + BACKUP_HEADER + sizeof(j->payload),
                                j->blob + BACKUP_HEADER, sizeof(j->payload),
                                (uint8_t *)&j->payload)) {
            j->result = FJ_RES_ERR; j->busy = false; return;
        }
        memcpy(master, j->payload.master, sizeof(master));
        master_available = true;
        fj_random(j->salt[1], 16);
        fj_random(j->salt[2], 16);
        fj_random(j->salt[3], 16);
        fj_random(j->salt[4], 16);
        memcpy(pass_salt, j->salt[1], 16);
        if (!job_begin_kdf(j, 1, j->a2, j->salt[1])) { j->result = FJ_RES_ERR; j->busy = false; return; }
        j->phase = 1; return;
    case 1:
        if (!kdf_chunk_done(&j->kdf[1])) return;
        if (!job_begin_kdf(j, 2, j->a2, j->salt[2])) { j->result = FJ_RES_ERR; j->busy = false; return; }
        j->phase = 2; return;
    case 2:
        if (!kdf_chunk_done(&j->kdf[2])) return;
        if (!job_begin_kdf(j, 3, j->a3, j->salt[3])) { j->result = FJ_RES_ERR; j->busy = false; return; }
        j->phase = 3; return;
    case 3:
        if (!kdf_chunk_done(&j->kdf[3])) return;
        if (!job_begin_kdf(j, 4, j->a3, j->salt[4])) { j->result = FJ_RES_ERR; j->busy = false; return; }
        j->phase = 4; return;
    case 4:
        if (!kdf_chunk_done(&j->kdf[4])) return;
        {
            uint8_t enc1[32], enc2[32];
            for (int i = 0; i < 32; i++) {
                enc1[i] = master[i] ^ j->kdf[2].out[i];
                enc2[i] = master[i] ^ j->kdf[4].out[i];
            }
            fj_store_begin();
            if (!fj_keys_backup_restore(&j->payload)) { fj_store_abort(); j->result = FJ_RES_ERR; j->busy = false; return; }
            memcpy(master, j->payload.master, sizeof(master));
            master_available = true;
            if (!fj_keys_set_passphrase(j->kdf[1].out, j->salt[1])) { fj_store_abort(); j->result = FJ_RES_ERR; j->busy = false; return; }
            pass_configured = true;
            memcpy(pass_hash, j->kdf[1].out, 32);
            memcpy(pass_salt, j->salt[1], 16);
            if (!fj_keys_set_master_pin_wrap(enc1, j->salt[2])) { fj_store_abort(); j->result = FJ_RES_ERR; j->busy = false; return; }
            if (!fj_keys_set_puk(j->kdf[3].out, j->salt[3])) { fj_store_abort(); j->result = FJ_RES_ERR; j->busy = false; return; }
            if (!fj_keys_set_master_puk_wrap(enc2, j->salt[4])) { fj_store_abort(); j->result = FJ_RES_ERR; j->busy = false; return; }
            if (!fj_store_commit()) { j->result = FJ_RES_ERR; j->busy = false; return; }
            fj_ctap2_forget_all();
            fj_ctap2_init();
            state = FJ_STATE_UNLOCKED;
            unlock_since = get_absolute_time();
            have_unlock_time = true;
            j->result = FJ_RES_OK;
            j->busy = false;
        }
        return;
    }
}

/* Dispatch ----------------------------------------------------------------- */
void fj_state_job_start(fj_state_job_t *j, fj_job_kind_t kind,
                        const char *a1, const char *a2, const char *a3) {
    memset(j, 0, sizeof(*j));
    j->kind = kind;
    j->result = FJ_RES_ERR;
    j->busy = true;
    if (a1) { strncpy(j->a1, a1, sizeof(j->a1) - 1); j->a1[sizeof(j->a1) - 1] = '\0'; }
    if (a2) { strncpy(j->a2, a2, sizeof(j->a2) - 1); j->a2[sizeof(j->a2) - 1] = '\0'; }
    if (a3) { strncpy(j->a3, a3, sizeof(j->a3) - 1); j->a3[sizeof(j->a3) - 1] = '\0'; }

    switch (kind) {
    case FJ_JOB_SETPASS:    job_start_setpass(j, j->a1); break;
    case FJ_JOB_UNLOCK:     job_start_unlock(j, j->a1); break;
    case FJ_JOB_SETPUK:     job_start_setpuk(j, j->a1); break;
    case FJ_JOB_UNLOCKPUK:
    case FJ_JOB_VERIFY_PUK: job_start_puk_verify(j, j->a1); break;
    case FJ_JOB_BACKUP:     job_start_backup(j, j->a1); break;
    case FJ_JOB_RESTORE:    job_start_restore(j, j->a1, j->a2, j->a3); break;
    default:                j->result = FJ_RES_ERR; j->busy = false; break;
    }
}

bool fj_state_job_step(fj_state_job_t *j) {
    if (!j->busy) return false;
    switch (j->kind) {
    case FJ_JOB_SETPASS:    job_run_setpass(j); break;
    case FJ_JOB_UNLOCK:     job_run_unlock(j); break;
    case FJ_JOB_SETPUK:     job_run_setpuk(j); break;
    case FJ_JOB_UNLOCKPUK:
    case FJ_JOB_VERIFY_PUK: job_run_puk(j); break;
    case FJ_JOB_BACKUP:     job_run_backup(j); break;
    case FJ_JOB_RESTORE:    job_run_restore(j); break;
    default:                j->result = FJ_RES_ERR; j->busy = false; break;
    }
    return j->busy;
}
