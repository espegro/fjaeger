#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "hardware/flash.h"
#include "flash_layout.h"
#include "factory_wipe.h"
#include "restore_journal.h"

_Alignas(4) uint8_t test_flash[PICO_FLASH_SIZE_BYTES];
static uint32_t cut_offset=UINT32_MAX;
static bool cut_program;
void flash_range_erase(uint32_t offset,size_t n) {
    assert(offset+n<=sizeof(test_flash));
    if (offset==cut_offset) n=64;
    memset(test_flash+offset,0xff,n);
}
void flash_range_program(uint32_t offset,const uint8_t *data,size_t n) {
    assert(offset+n<=sizeof(test_flash));
    if (cut_program) n=20;
    memcpy(test_flash+offset,data,n);
}
static void fixture(void) {
    memset(test_flash,0xff,sizeof(test_flash));
    /* Fill all reserved store areas, leaving both journal sectors erased. */
    memset(test_flash+FJ_HMAC_CONFIG_OFFSET,0x12,2u*FLASH_SECTOR_SIZE+FJ_KEYS_SLOT_SIZE+FLASH_SECTOR_SIZE);
    memset(test_flash+FJ_HMAC_STORE_OFFSET,0x34,
           PICO_FLASH_SIZE_BYTES-FJ_HMAC_STORE_OFFSET);
    test_flash[FJ_HMAC_CONFIG_OFFSET-1]=0x56;
    assert(fj_restore_journal_init());
}
static void check_erased(uint32_t start,size_t n) {
    for (size_t i=0;i<n;i++) assert(test_flash[start+i]==0xff);
}
int main(void) {
    const uint32_t cuts[]={FJ_HMAC_CONFIG_OFFSET,FJ_KEYS_STAGE_OFFSET,FJ_HMAC_STAGE_OFFSET,
                           FJ_HMAC_STORE_OFFSET,FJ_KEYS_STORE_OFFSET};
    for (size_t i=0;i<sizeof(cuts)/sizeof(cuts[0]);i++) {
        fixture(); cut_offset=cuts[i];
        assert(!fj_factory_wipe_start());
        cut_offset=UINT32_MAX;
        assert(fj_restore_journal_init());
        fj_restore_phase_t phase; fj_restore_plan_t plan;
        assert(fj_restore_journal_read(&phase,&plan) && phase==FJ_RESTORE_WIPING);
        assert(fj_factory_wipe_recover());
        assert(fj_restore_journal_init());
        assert(fj_restore_journal_read(&phase,&plan) && phase==FJ_RESTORE_CLEAN);
        check_erased(FJ_HMAC_CONFIG_OFFSET,2u*FLASH_SECTOR_SIZE+FJ_KEYS_SLOT_SIZE+FLASH_SECTOR_SIZE);
        check_erased(FJ_HMAC_STORE_OFFSET,PICO_FLASH_SIZE_BYTES-FJ_HMAC_STORE_OFFSET);
        assert(test_flash[FJ_HMAC_CONFIG_OFFSET-1]==0x56);
    }
    fixture(); cut_program=true;
    assert(!fj_factory_wipe_start()); cut_program=false;
    assert(test_flash[FJ_KEYS_STAGE_OFFSET]==0x12);
    assert(test_flash[FJ_HMAC_STORE_OFFSET]==0x34);
    assert(!fj_restore_journal_init()); /* torn intent fails closed */
    fixture(); assert(fj_restore_journal_begin_wipe());
    cut_program=true; assert(!fj_factory_wipe_recover()); cut_program=false;
    check_erased(FJ_HMAC_CONFIG_OFFSET,2u*FLASH_SECTOR_SIZE+FJ_KEYS_SLOT_SIZE+FLASH_SECTOR_SIZE);
    check_erased(FJ_HMAC_STORE_OFFSET,PICO_FLASH_SIZE_BYTES-FJ_HMAC_STORE_OFFSET);
    assert(!fj_restore_journal_init()); /* torn completion also fails closed */
    fixture(); fj_restore_plan_t plan={0}; plan.transaction_id[0]=1;
    assert(fj_restore_journal_begin(&plan));
    assert(!fj_factory_wipe_start());
    assert(test_flash[FJ_KEYS_STAGE_OFFSET]==0x12);
    puts("factory wipe intent, interrupted erasure and boundaries: ok");
}
