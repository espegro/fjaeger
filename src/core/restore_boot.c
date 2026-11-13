#include "restore_boot.h"
#include "restore_coordinator.h"
#include "keys_stage.h"
#include "keys_stage_internal.h"
#include "hmac_store.h"
#include "factory_wipe.h"
#include "restore_internal.h"
#include <stddef.h>

/* Boot recovery never starts a restore and has no plaintext backup in RAM. */
static bool no_stage(void *ctx,const fj_restore_plan_t *p) { (void)ctx; (void)p; return false; }
static bool staged(void *ctx,const fj_restore_plan_t *p) {
    (void)ctx; return fj_keys_stage_verify(p) && fj_hmac_stage_verify(p);
}
static bool old_active(void *ctx,const fj_restore_plan_t *p) {
    (void)ctx; return fj_keys_restore_old_active(p) && fj_hmac_restore_old_active(p);
}
static bool discard(void *ctx,const fj_restore_plan_t *p) {
    (void)ctx; (void)p; return fj_keys_stage_discard() && fj_hmac_stage_discard();
}
static bool activate_keys(void *ctx,const fj_restore_plan_t *p) {
    (void)ctx; return fj_keys_stage_activate(p);
}
static bool activate_hmac(void *ctx,const fj_restore_plan_t *p) {
    (void)ctx; return fj_hmac_stage_activate(p);
}
static bool new_active(void *ctx,const fj_restore_plan_t *p) {
    (void)ctx; return fj_keys_restore_new_active(p) && fj_hmac_restore_new_active(p);
}
static bool previous(void *ctx,const fj_restore_plan_t *p) {
    (void)ctx;
    return fj_keys_restore_discard_previous(p) && fj_hmac_restore_discard_previous(p);
}
fj_restore_ops_t fj_restore_store_ops(void) {
    const fj_restore_ops_t ops={NULL,no_stage,no_stage,staged,old_active,discard,
                                activate_keys,activate_hmac,new_active,previous};
    return ops;
}
bool fj_restore_boot_recover(void) {
    if (!fj_restore_journal_init()) return false;
    fj_restore_phase_t phase; fj_restore_plan_t plan;
    if (!fj_restore_journal_read(&phase,&plan)) return false;
    if (phase==FJ_RESTORE_WIPING) return fj_factory_wipe_recover();
    const fj_restore_ops_t ops=fj_restore_store_ops();
    return fj_restore_recover(&ops);
}
