#ifndef FJ_RESTORE_COORDINATOR_H
#define FJ_RESTORE_COORDINATOR_H
#include <stdbool.h>
#include "restore_journal.h"

/* All callbacks must be power-loss-safe and idempotent. Caller must authenticate
 * the backup, prepare a plan, and block all normal service before invoking. */
typedef struct {
    void *ctx;
    /* Stage writes only reserved staging areas; they cannot become visible. */
    bool (*stage_keys)(void *, const fj_restore_plan_t *);
    bool (*stage_hmac)(void *, const fj_restore_plan_t *);
    /* After a crash, verify_staged must also accept already-activated records,
     * while still checking transaction identity, generation and digest. */
    bool (*verify_staged)(void *, const fj_restore_plan_t *);
    bool (*verify_old_active)(void *, const fj_restore_plan_t *);
    bool (*discard_staged)(void *, const fj_restore_plan_t *);
    /* Activation must be idempotent and must preserve enough data for a
     * repeated verify_staged after a crash between activations. */
    bool (*activate_keys)(void *, const fj_restore_plan_t *);
    bool (*activate_hmac)(void *, const fj_restore_plan_t *);
    /* Must validate both active records against the plan even after the
     * staging sectors have been partially or completely erased. */
    bool (*verify_new_active)(void *, const fj_restore_plan_t *);
    /* FINALIZING only: remove old inactive copies; repeat safely after reset. */
    bool (*discard_previous)(void *, const fj_restore_plan_t *);
} fj_restore_ops_t;

/* true means the journal is clean and normal service may be enabled. false
 * means recovery required; it must NEVER be interpreted as a clean state. */
bool fj_restore_recover(const fj_restore_ops_t *ops);
/* Begin after backup validation. A failure leaves a recovery-only journal. */
bool fj_restore_execute(const fj_restore_ops_t *ops, const fj_restore_plan_t *plan);
#endif
