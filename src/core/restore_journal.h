#ifndef FJ_RESTORE_JOURNAL_H
#define FJ_RESTORE_JOURNAL_H
#include <stdbool.h>
#include <stdint.h>

/* CRC detects accidental damage only; it is not tamper/rollback protection.
 * Combined user-facing restore and cleanup are not yet connected. */
typedef enum {
    FJ_RESTORE_CLEAN = 0,
    FJ_RESTORE_PREPARED = 1,
    FJ_RESTORE_COMMITTED = 2,
    FJ_RESTORE_FINALIZING = 3,
    FJ_RESTORE_WIPING = 4
} fj_restore_phase_t;
typedef struct {
    uint8_t transaction_id[16];
    uint32_t old_keys_generation, old_hmac_generation;
    uint32_t new_keys_generation, new_hmac_generation;
    uint8_t new_keys_digest[32], new_hmac_digest[32];
} fj_restore_plan_t;

/* Inspect both A/B journal sectors. Returns false on corrupt or unsupported
 * state; callers must fail closed and never treat false as CLEAN. */
bool fj_restore_journal_init(void);
bool fj_restore_journal_read(fj_restore_phase_t *phase, fj_restore_plan_t *plan);
/* A committed decision must match the complete transaction plan. */
bool fj_restore_journal_authorizes_commit(const fj_restore_plan_t *plan);
bool fj_restore_journal_authorizes_finalize(const fj_restore_plan_t *plan);
/* begin requires a random nonzero transaction ID and no active transaction. */
bool fj_restore_journal_begin(const fj_restore_plan_t *plan);
/* Caller must first durably stage and verify both stores against the plan. */
bool fj_restore_journal_commit(void);
/* After both new records are active and verified, persist the decision that
 * recovery must finish cleanup without needing either staging copy. */
bool fj_restore_journal_finalize(void);
/* Caller must first verify the old pair is intact. Valid only before commit. */
bool fj_restore_journal_abort(void);
/* Caller must verify both new stores and complete staging cleanup. */
bool fj_restore_journal_finish(void);
/* Persistent factory-wipe intent; valid only from CLEAN. While WIPING, boot
 * must complete verified erasure before allowing service or clearing it. */
bool fj_restore_journal_begin_wipe(void);
bool fj_restore_journal_finish_wipe(void);
#endif
