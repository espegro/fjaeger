#include <assert.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include "hardware/flash.h"
#include "keys_stage.h"
#include "flash_layout.h"
_Alignas(4) uint8_t test_flash[PICO_FLASH_SIZE_BYTES];
static bool cut_program, cut_erase;
void flash_range_erase(uint32_t offset,size_t length) {
    assert(offset+length<=sizeof(test_flash));
    if (cut_erase) length=64;
    memset(test_flash+offset,0xff,length);
}
void flash_range_program(uint32_t offset,const uint8_t *data,size_t length) {
    assert(offset+length<=sizeof(test_flash));
    if (cut_program) length=64;
    memcpy(test_flash+offset,data,length);
}
#include "../src/core/keys.c"
int main(void) {
    memset(test_flash,0xff,sizeof(test_flash));
    test_flash[FJ_KEYS_STAGE_OFFSET-1]=0x31;
    test_flash[FJ_HMAC_STAGE_OFFSET]=0x32;
    fj_keys_init(); assert(fj_keys_ready());
    assert(fj_keys_set_timeout(123));
    fj_restore_plan_t plan={0}; plan.transaction_id[0]=4;
    plan.old_keys_generation=active_generation;
    plan.new_keys_generation=active_generation+1;
    uint8_t digest[32];
    assert(!fj_keys_stage_digest(&plan,digest)); /* no transaction */
    fj_store_begin();
    assert(!fj_keys_stage_digest(&plan,digest)); /* no change */
    assert(fj_keys_set_timeout(456));
    uint8_t hash[32]={7}, salt[16]={8};
    assert(fj_keys_set_passphrase(hash,salt));
    assert(fj_keys_stage_digest(&plan,plan.new_keys_digest));
    fj_restore_plan_t wrong=plan; wrong.transaction_id[0]++;
    assert(!fj_keys_stage_write(&wrong));
    cut_program=true; assert(!fj_keys_stage_write(&plan)); cut_program=false;
    assert(!fj_keys_stage_verify(&plan));
    assert(!fj_keys_stage_write(&plan)); /* preserve torn stage for recovery */
    fj_store_abort(); fj_keys_init();
    uint32_t timeout=0; assert(fj_keys_get_timeout(&timeout) && timeout==123);
    assert(!fj_keys_passphrase_configured());
    assert(fj_keys_stage_discard());
    fj_store_begin(); assert(fj_keys_set_timeout(456));
    assert(fj_keys_set_passphrase(hash,salt));
    assert(fj_keys_stage_write(&plan));
    assert(fj_keys_stage_write(&plan));
    assert(fj_keys_stage_verify(&plan));
    wrong=plan; wrong.new_keys_digest[0]^=1;
    assert(!fj_keys_stage_verify(&wrong));
    fj_store_abort(); fj_keys_init();
    assert(fj_keys_get_timeout(&timeout) && timeout==123);
    assert(!fj_keys_passphrase_configured());
    assert(fj_keys_stage_verify(&plan));
    test_flash[FJ_KEYS_STAGE_OFFSET+100]^=1;
    assert(!fj_keys_stage_verify(&plan));
    cut_erase=true; assert(!fj_keys_stage_discard()); cut_erase=false;
    assert(fj_keys_stage_discard());
    assert(test_flash[FJ_KEYS_STAGE_OFFSET-1]==0x31);
    assert(test_flash[FJ_HMAC_STAGE_OFFSET]==0x32);
    puts("key staging isolation and interrupted writes: ok");
}
