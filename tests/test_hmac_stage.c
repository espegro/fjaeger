#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "hardware/flash.h"
#include "flash_layout.h"
#include "hmac_store.h"

_Alignas(4) uint8_t test_flash[PICO_FLASH_SIZE_BYTES];
static bool cut_program, cut_erase;
void fj_random(void *p,size_t n) { memset(p,0x42,n); }
void flash_range_erase(uint32_t off,size_t n) {
    assert(off+n<=sizeof(test_flash));
    if (cut_erase) n=64;
    memset(test_flash+off,0xff,n);
}
void flash_range_program(uint32_t off,const uint8_t *p,size_t n) {
    assert(off+n<=sizeof(test_flash));
    if (cut_program) n=64;
    memcpy(test_flash+off,p,n);
}
int main(void) {
    memset(test_flash,0xff,sizeof(test_flash));
    test_flash[FJ_HMAC_STAGE_OFFSET-1]=0x51;
    test_flash[FJ_RESTORE_JOURNAL_OFFSET]=0x52;
    assert(fj_hmac_store_init());
    uint8_t root[32]={1}, otp[32]={2}, salt[16]={3}, nonce[12]={4};
    fj_hmac_root_record_t wrapped;
    assert(fj_hmac_root_create(&wrapped,FJ_HMAC_ROOT_OTP,root,otp,salt,nonce));
    assert(fj_hmac_store_provision_root(&wrapped,otp));
    uint8_t material[FJ_HMAC_MATERIAL_LEN]={5};
    fj_hmac_credential_t old={0}, next={0}, got;
    old.credential_id[0]=6; old.nonce[0]=7;
    next.credential_id[0]=8; next.nonce[0]=9;
    assert(fj_hmac_credential_seal(&old,root,material));
    assert(fj_hmac_credential_seal(&next,root,material));
    assert(fj_hmac_store_put(&old)); /* generation 2 */
    fj_hmac_snapshot_t snapshot={0}; memcpy(snapshot.root,root,32);
    snapshot.entries[0].used=1; snapshot.entries[0].credential=next;
    fj_restore_plan_t plan={0}; plan.transaction_id[0]=10;
    plan.old_hmac_generation=2; plan.new_hmac_generation=3;
    uint8_t wrong_otp[32]={0}, digest[32];
    assert(!fj_hmac_stage_digest(&snapshot,&wrapped,wrong_otp,&plan,digest));
    assert(fj_hmac_stage_digest(&snapshot,&wrapped,otp,&plan,plan.new_hmac_digest));
    fj_restore_plan_t wrong=plan; wrong.transaction_id[0]++;
    assert(!fj_hmac_stage_write(&snapshot,&wrapped,otp,&wrong));
    cut_program=true; assert(!fj_hmac_stage_write(&snapshot,&wrapped,otp,&plan));
    cut_program=false;
    assert(!fj_hmac_stage_verify(&plan));
    assert(!fj_hmac_stage_write(&snapshot,&wrapped,otp,&plan)); /* torn record retained */
    assert(fj_hmac_store_init());
    assert(fj_hmac_store_get(old.credential_id,&got));
    assert(!fj_hmac_store_get(next.credential_id,&got));
    assert(fj_hmac_stage_discard());
    assert(fj_hmac_stage_write(&snapshot,&wrapped,otp,&plan));
    assert(fj_hmac_stage_write(&snapshot,&wrapped,otp,&plan)); /* idempotent */
    assert(fj_hmac_stage_verify(&plan));
    assert(!fj_hmac_stage_verify(&wrong));
    wrong=plan; wrong.new_hmac_digest[0]^=1;
    assert(!fj_hmac_stage_verify(&wrong));
    assert(!fj_hmac_stage_write(&snapshot,&wrapped,otp,&wrong));
    assert(fj_hmac_store_init());
    assert(fj_hmac_store_get(old.credential_id,&got));
    assert(!fj_hmac_store_get(next.credential_id,&got));
    test_flash[FJ_HMAC_STAGE_OFFSET+100]^=1;
    assert(!fj_hmac_stage_verify(&plan));
    cut_erase=true; assert(!fj_hmac_stage_discard()); cut_erase=false;
    assert(fj_hmac_stage_discard());
    assert(test_flash[FJ_HMAC_STAGE_OFFSET-1]==0x51);
    assert(test_flash[FJ_RESTORE_JOURNAL_OFFSET]==0x52);
    puts("hmac staging isolation and interrupted writes: ok");
}
