#include "restore_coordinator.h"
#include <stddef.h>

static bool valid_ops(const fj_restore_ops_t *o) {
    return o && o->stage_keys && o->stage_hmac && o->verify_staged &&
           o->verify_old_active && o->discard_staged && o->activate_keys &&
           o->activate_hmac && o->verify_new_active && o->discard_previous;
}
bool fj_restore_recover(const fj_restore_ops_t *o) {
    if (!valid_ops(o)) return false;
    fj_restore_phase_t phase; fj_restore_plan_t plan;
    if (!fj_restore_journal_read(&phase,&plan)) return false;
    if (phase == FJ_RESTORE_CLEAN) return true;
    if (phase == FJ_RESTORE_PREPARED) {
        /* Before a durable commit decision, only the intact old pair may be
         * restored. An incomplete stage must not become visible. */
        if (!o->verify_old_active(o->ctx,&plan) ||
            !o->discard_staged(o->ctx,&plan) ||
            !o->verify_old_active(o->ctx,&plan)) return false;
        return fj_restore_journal_abort();
    }
    if (phase == FJ_RESTORE_COMMITTED) {
        /* Commit is the point of no return. Complete both activations, even
         * after a reboot between them; never fall back to the old pair. */
        if (!o->verify_staged(o->ctx,&plan) ||
            !o->activate_keys(o->ctx,&plan) ||
            !o->activate_hmac(o->ctx,&plan) ||
            !o->verify_new_active(o->ctx,&plan)) return false;
        if (!fj_restore_journal_finalize()) return false;
        phase=FJ_RESTORE_FINALIZING;
    }
    if (phase == FJ_RESTORE_FINALIZING) {
        /* The durable decision means both new copies were verified. Staging
         * may already be partly erased; verify active images independently. */
        if (!o->verify_new_active(o->ctx,&plan) ||
            !o->discard_previous(o->ctx,&plan) ||
            !o->discard_staged(o->ctx,&plan) ||
            !o->verify_new_active(o->ctx,&plan)) return false;
        return fj_restore_journal_finish();
    }
    return false;
}
bool fj_restore_execute(const fj_restore_ops_t *o, const fj_restore_plan_t *plan) {
    if (!valid_ops(o) || !plan) return false;
    if (!fj_restore_journal_begin(plan)) return false;
    if (!o->stage_keys(o->ctx,plan) || !o->stage_hmac(o->ctx,plan) ||
        !o->verify_staged(o->ctx,plan)) return false;
    if (!fj_restore_journal_commit()) return false;
    return fj_restore_recover(o);
}
