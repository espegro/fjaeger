#ifndef FJ_KEYS_STAGE_H
#define FJ_KEYS_STAGE_H
#include <stdbool.h>
#include <stdint.h>
#include "restore_journal.h"

/* Internal prototype: caller must authenticate and fully validate the backup,
 * block normal service, and construct a complete transaction including new
 * passphrase/PUK verifiers and both rewrapped master keys. Never stage the
 * plaintext backup master. After staging, abort the in-memory transaction.
 * No activation, boot recovery or user-facing restore is connected yet. */
bool fj_keys_stage_digest(const fj_restore_plan_t *plan, uint8_t digest[32]);
bool fj_keys_stage_write(const fj_restore_plan_t *plan);
bool fj_keys_stage_verify(const fj_restore_plan_t *plan);
/* Only a matching COMMITTED journal permits activation. Normal services must
 * remain blocked until both stores are verified and the journal is clean. */
bool fj_keys_stage_activate(const fj_restore_plan_t *plan);
bool fj_keys_stage_is_active(const fj_restore_plan_t *plan);
bool fj_keys_restore_new_active(const fj_restore_plan_t *plan);
bool fj_keys_restore_discard_previous(const fj_restore_plan_t *plan);
/* Only discard on a recovery decision that does not require the stage. */
bool fj_keys_stage_discard(void);
#endif
