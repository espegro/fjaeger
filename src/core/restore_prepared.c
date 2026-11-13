#include "restore_prepared.h"
#include "restore_internal.h"
#include "keys_stage.h"
#include "keys_stage_internal.h"
#include "keys.h"
#include "crypto.h"
#include <string.h>

typedef struct {
    const fj_hmac_snapshot_t *snapshot;
    const fj_hmac_root_record_t *root;
    const uint8_t *otp;
} stage_context_t;
static bool stage_keys(void *ctx,const fj_restore_plan_t *plan) {
    (void)ctx; return fj_keys_stage_write(plan);
}
static bool stage_hmac(void *ctx,const fj_restore_plan_t *plan) {
    const stage_context_t *c=ctx;
    return fj_hmac_stage_write(c->snapshot,c->root,c->otp,plan);
}
bool fj_restore_prepared(const fj_hmac_snapshot_t *snapshot,
                         const fj_hmac_root_record_t *root,const uint8_t otp[32],
                         const uint8_t transaction_id[16]) {
    fj_restore_plan_t plan={0}; bool ok=false;
    if (!snapshot || !root || !transaction_id) goto done;
    memcpy(plan.transaction_id,transaction_id,sizeof(plan.transaction_id));
    if (!fj_keys_restore_staging_generation(&plan.old_keys_generation) ||
        !fj_hmac_restore_generation(&plan.old_hmac_generation)) goto done;
    plan.new_keys_generation=plan.old_keys_generation+1u;
    plan.new_hmac_generation=plan.old_hmac_generation+1u;
    if (!fj_keys_stage_digest(&plan,plan.new_keys_digest) ||
        !fj_hmac_stage_digest(snapshot,root,otp,&plan,plan.new_hmac_digest)) goto done;
    stage_context_t ctx={snapshot,root,otp};
    fj_restore_ops_t ops=fj_restore_store_ops();
    ops.ctx=&ctx; ops.stage_keys=stage_keys; ops.stage_hmac=stage_hmac;
    if (!ops.verify_old_active(ops.ctx,&plan)) goto done;
    ok=fj_restore_execute(&ops,&plan);
done:
    fj_store_abort();
    if (ok) {
        /* Refresh in-memory views only once both new copies are committed,
         * checked, and the journal is clean. Other caches are the caller's
         * responsibility before it reopens any services. */
        fj_keys_init();
        ok=fj_keys_ready() && fj_hmac_store_init();
    }
    fj_secure_zero(&plan,sizeof(plan));
    return ok;
}
