/*
 * Fjaeger - core state machine.
 *
 * The device can be LOCKED or UNLOCKED. While locked, no signing,
 * decryption or credential operations are permitted; only the serial
 * console (lock / status / help) is available. Unlocking requires the
 * PIN to be verified over the serial console.
 */
#ifndef FJAEGER_STATE_H
#define FJAEGER_STATE_H

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    FJ_STATE_LOCKED = 0,
    FJ_STATE_UNLOCKED,
} fj_state_t;

#define FJ_DEFAULT_TIMEOUT_SEC 900u

/* Boot the state machine. Clears any stale in-RAM state. */
void fj_state_init(void);

/* Current lock state. */
fj_state_t fj_state_get(void);

/* Whether a PIN has been provisioned. */
bool fj_state_pin_configured(void);

/* Lock immediately (manual lock or auto-relock timeout). */
void fj_state_lock(void);

/* Attempt to unlock with the given PIN. Returns true on success. */
bool fj_state_unlock(const char *pin);

/* Whether the device PIN is currently blocked (needs a PUK). */
bool fj_state_pin_blocked(void);

/* Result of a PUK unlock attempt. */
typedef enum {
    FJ_PUK_OK    = 0, /* correct PUK, device unlocked, counters reset */
    FJ_PUK_WRONG = 1, /* wrong PUK (counted) */
    FJ_PUK_UNSET = 2, /* no PUK has been provisioned */
    FJ_PUK_WIPED = 3, /* too many wrong PUKs, device wiped */
} fj_puk_result_t;

/* Attempt to unblock the device PIN with the recovery PUK. */
fj_puk_result_t fj_state_unlock_puk(const char *puk);

/* Verify the recovery PUK without unlocking the device. Used by other
 * subsystems that have their own blocked state. A correct PUK resets the
 * shared PUK failure counter. */
fj_puk_result_t fj_state_verify_puk(const char *puk);

/* Securely forget all persistent and live credentials, keys and PIN state. */
void fj_state_factory_reset(void);

/* Set (or change) the recovery PUK. Requires the device to be unlocked. */
bool fj_state_set_puk(const char *puk);

/* Set (or change) the PIN. Stored as a SHA-256 hash. Returns true on
 * success. */
bool fj_state_set_pin(const char *pin);

/* The credential wrapping key (CWK), held in RAM only while the device is
 * unlocked. ctap2.c uses it to encrypt/decrypt credential private keys at
 * rest. Returns true and copies the 32-byte CWK into 'out' if it is
 * currently available (device unlocked by entering the device PIN). Returns
 * false when it is not derivable (e.g. unlocked via PUK, or no PIN set). */
bool fj_state_cwk(uint8_t out[32]);

/* Backup the master key and all credential/profile state to a file on the
 * MSC drive, encrypted with the given backup password. Requires the device
 * to be unlocked (so the master key is available). The file is deleted when
 * the drive is locked. Returns true on success. */
bool fj_state_backup_write(const char *password);

/* Restore a backup file from the MSC drive. Decrypts with the backup
 * password, imports the credentials, profiles and active profile, and
 * re-wraps the recovered master key with the supplied new device PIN and
 * new recovery PUK in one atomic step. The device is left unlocked. Returns
 * true on success. */
bool fj_state_backup_restore(const char *password, const char *new_pin,
                             const char *new_puk);

/* Erase a profile and every credential bound to it as one consistent
 * operation: first the live CTAP2 cache is purged, then the persistent
 * store is updated and flushed. Rejects erasing the active profile. */
bool fj_state_profile_erase(unsigned profile_id);

/* Called from the main loop to enforce the auto-relock timeout. */
void fj_state_tick(void);

/* Brute-force delay gate (RAM-only, monotonic, exponential backoff).
 *
 * A failed PIN / PUK / disk-PIN attempt imposes a growing delay before the
 * next attempt on that input is accepted, so an online attacker cannot
 * brute-force a passphrase rapidly. The persistent failure counters (which
 * block after FJ_MAX_PIN_FAILS / FJ_MAX_PUK_FAILS and survive reboot) remain
 * the hard stop; this only slows the rate of live attempts. Each context has
 * its own independent delay, mirroring the separate persistent counters.
 *
 *   fj_state_brute_ok(ctx)      -> true if an attempt is currently permitted.
 *   fj_state_brute_failure(ctx) -> record a failed attempt (grows the delay).
 *   fj_state_brute_success(ctx) -> clear the delay on a correct passphrase. */
typedef enum {
    FJ_BRUTE_PIN,   /* device PIN (console UNLOCK + CTAP2 getPinToken) */
    FJ_BRUTE_PUK,   /* recovery PUK (UNLOCKPUK) */
    FJ_BRUTE_DISK,  /* disk PIN (DISK UNLOCK) */
} fj_brute_ctx_t;

void fj_state_brute_success(fj_brute_ctx_t ctx);
void fj_state_brute_failure(fj_brute_ctx_t ctx);
bool fj_state_brute_ok(fj_brute_ctx_t ctx);

/* Persist an auto-relock timeout in seconds (0 disables). */
bool fj_state_set_timeout(uint32_t seconds);

/* Get the configured auto-relock timeout in seconds. */
uint32_t fj_state_timeout(void);

#ifdef __cplusplus
}
#endif

#endif /* FJAEGER_STATE_H */
