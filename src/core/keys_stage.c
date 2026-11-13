#include "keys_stage.h"
#include "keys_stage_internal.h"
#include "flash_layout.h"
#include "crypto.h"
#include "hardware/sync.h"
#include <stddef.h>
#include <string.h>

#define STAGE_MAGIC 0x464a4b54u
typedef struct {
    uint32_t magic, version, size;
    uint8_t transaction_id[16];
    uint32_t alignment;
    uint8_t image[];
} stage_header_t;
static uint8_t buffer[FJ_KEYS_SLOT_SIZE] __attribute__((aligned(4)));

static bool id_valid(const uint8_t id[16]) {
    uint8_t any=0; for (unsigned i=0;i<16;i++) any|=id[i]; return any!=0;
}
static bool erased(void) {
    const uint8_t *p=(const void *)(XIP_BASE+FJ_KEYS_STAGE_OFFSET);
    for (size_t i=0;i<FJ_KEYS_SLOT_SIZE;i++) if(p[i]!=0xff) return false;
    return true;
}
static bool build(const fj_restore_plan_t *plan, size_t *length) {
    if (!plan || !id_valid(plan->transaction_id)) return false;
    memset(buffer,0,sizeof(buffer));
    stage_header_t *h=(void *)buffer;
    size_t n=0;
    if (!fj_keys_stage_image(h->image,sizeof(buffer)-sizeof(*h),&n,plan)) return false;
    h->magic=STAGE_MAGIC; h->version=1; h->size=(uint32_t)n;
    memcpy(h->transaction_id,plan->transaction_id,16);
    *length=sizeof(*h)+n;
    return true;
}
bool fj_keys_stage_digest(const fj_restore_plan_t *plan, uint8_t digest[32]) {
    if (!digest) return false;
    memset(digest,0,32); size_t length=0;
    bool ok=build(plan,&length);
    if (ok) fj_sha256(buffer,length,digest);
    fj_secure_zero(buffer,sizeof(buffer)); return ok;
}
bool fj_keys_stage_verify(const fj_restore_plan_t *plan) {
    if (!plan || !id_valid(plan->transaction_id) ||
        plan->new_keys_generation!=plan->old_keys_generation+1u) return false;
    const stage_header_t *h=(const void *)(XIP_BASE+FJ_KEYS_STAGE_OFFSET);
    if (h->magic!=STAGE_MAGIC || h->version!=1 || h->alignment!=0 ||
        h->size>FJ_KEYS_SLOT_SIZE-sizeof(*h) ||
        memcmp(h->transaction_id,plan->transaction_id,16)!=0 ||
        !fj_keys_stage_image_valid(h->image,h->size,plan->new_keys_generation)) return false;
    uint8_t digest[32]; fj_sha256((const uint8_t *)h,sizeof(*h)+h->size,digest);
    bool ok=fj_ct_equal(digest,plan->new_keys_digest,sizeof(digest));
    fj_secure_zero(digest,sizeof(digest)); return ok;
}
bool fj_keys_stage_write(const fj_restore_plan_t *plan) {
    if (!plan) return false;
    if (!erased()) return fj_keys_stage_verify(plan);
    size_t length=0; bool ok=build(plan,&length); uint8_t digest[32]={0};
    if (ok) { fj_sha256(buffer,length,digest); ok=fj_ct_equal(digest,plan->new_keys_digest,32); }
    if (ok) {
        size_t program_size=(length+FLASH_PAGE_SIZE-1u)/FLASH_PAGE_SIZE*FLASH_PAGE_SIZE;
        uint32_t ints=save_and_disable_interrupts();
        flash_range_program(FJ_KEYS_STAGE_OFFSET,buffer,program_size);
        restore_interrupts(ints);
        ok=fj_keys_stage_verify(plan);
    }
    fj_secure_zero(digest,sizeof(digest)); fj_secure_zero(buffer,sizeof(buffer)); return ok;
}
bool fj_keys_stage_activate(const fj_restore_plan_t *plan) {
    if (!fj_restore_journal_authorizes_commit(plan) || !fj_keys_stage_verify(plan)) return false;
    const stage_header_t *h=(const void *)(XIP_BASE+FJ_KEYS_STAGE_OFFSET);
    return fj_keys_stage_activate_image(h->image,h->size,plan);
}
bool fj_keys_stage_is_active(const fj_restore_plan_t *plan) {
    if (!fj_keys_stage_verify(plan)) return false;
    const stage_header_t *h=(const void *)(XIP_BASE+FJ_KEYS_STAGE_OFFSET);
    return fj_keys_stage_image_active(h->image,h->size,plan);
}
bool fj_keys_restore_new_active(const fj_restore_plan_t *plan) {
    if (!plan || !id_valid(plan->transaction_id) ||
        plan->new_keys_generation!=plan->old_keys_generation+1u) return false;
    memset(buffer,0,sizeof(buffer)); stage_header_t *h=(void *)buffer; size_t n=0;
    bool ok=fj_keys_restore_copy_active(h->image,sizeof(buffer)-sizeof(*h),&n,
                                        plan->new_keys_generation);
    if (ok) {
        h->magic=STAGE_MAGIC; h->version=1; h->size=(uint32_t)n;
        memcpy(h->transaction_id,plan->transaction_id,16);
        uint8_t digest[32]; fj_sha256(buffer,sizeof(*h)+n,digest);
        ok=fj_ct_equal(digest,plan->new_keys_digest,32);
        fj_secure_zero(digest,sizeof(digest));
    }
    fj_secure_zero(buffer,sizeof(buffer)); return ok;
}
bool fj_keys_restore_discard_previous(const fj_restore_plan_t *plan) {
    if (!fj_restore_journal_authorizes_finalize(plan) || !fj_keys_restore_new_active(plan)) return false;
    return fj_keys_restore_erase_inactive(plan->new_keys_generation) &&
           fj_keys_restore_new_active(plan);
}
bool fj_keys_stage_discard(void) {
    if (erased()) return true;
    uint32_t ints=save_and_disable_interrupts();
    flash_range_erase(FJ_KEYS_STAGE_OFFSET,FJ_KEYS_SLOT_SIZE);
    restore_interrupts(ints);
    return erased();
}
