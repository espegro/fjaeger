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

/* Boot the state machine. Clears any stale in-RAM state. */
void fj_state_init(void);

/* Current lock state. */
fj_state_t fj_state_get(void);

/* Lock immediately (manual lock or auto-relock timeout). */
void fj_state_lock(void);

/* Attempt to unlock with the given PIN. Returns true on success. */
bool fj_state_unlock(const char *pin);

/* Set (or change) the PIN. Stored as a SHA-256 hash. Returns true on
 * success. */
bool fj_state_set_pin(const char *pin);

/* Called from the main loop to enforce the auto-relock timeout. */
void fj_state_tick(void);

/* Set an auto-relock timeout in seconds (0 disables). */
void fj_state_set_timeout(uint32_t seconds);

/* Get the configured auto-relock timeout in seconds. */
uint32_t fj_state_timeout(void);

#ifdef __cplusplus
}
#endif

#endif /* FJAEGER_STATE_H */