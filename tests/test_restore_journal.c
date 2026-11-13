#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "hardware/flash.h"
#include "restore_journal.h"
_Alignas(4) uint8_t test_flash[PICO_FLASH_SIZE_BYTES];
static bool fail_program;
void flash_range_erase(uint32_t offset, size_t len) { assert(offset+len<=sizeof(test_flash)); memset(test_flash+offset,0xff,len); }
void flash_range_program(uint32_t offset,const uint8_t *src,size_t len) { assert(offset+len<=sizeof(test_flash)); if(fail_program) len=20; memcpy(test_flash+offset,src,len); }
static void check(fj_restore_phase_t wanted,const fj_restore_plan_t *expected) {
    fj_restore_phase_t p; fj_restore_plan_t r;
    assert(fj_restore_journal_read(&p,&r) && p==wanted);
    if(expected) assert(memcmp(&r,expected,sizeof(r))==0);
}
static void torn_transition(unsigned step) {
    memset(test_flash,0xff,sizeof(test_flash));
    fail_program=false;
    assert(fj_restore_journal_init());
    fj_restore_plan_t p={0}; p.transaction_id[0]=1;
    if(step>=1) assert(fj_restore_journal_begin(&p));
    if(step==2 || step==4) assert(fj_restore_journal_commit());
    if(step==4) assert(fj_restore_journal_finalize());
    fail_program=true;
    if(step==0) assert(!fj_restore_journal_begin(&p));
    else if(step==1) assert(!fj_restore_journal_commit());
    else if(step==2) assert(!fj_restore_journal_finalize());
    else if(step==3) assert(!fj_restore_journal_abort());
    else assert(!fj_restore_journal_finish());
    fail_program=false;
    assert(!fj_restore_journal_init());
    fj_restore_phase_t phase; fj_restore_plan_t ignored;
    assert(!fj_restore_journal_read(&phase,&ignored));
}
int main(void) {
    memset(test_flash,0xff,sizeof(test_flash));
    const size_t start=PICO_FLASH_SIZE_BYTES-2u*FLASH_SECTOR_SIZE-2u*(32u*1024u)-4u*FLASH_SECTOR_SIZE;
    test_flash[start-1]=0x55; test_flash[start+2u*FLASH_SECTOR_SIZE]=0xaa;
    assert(fj_restore_journal_init()); check(FJ_RESTORE_CLEAN,NULL);
    fj_restore_plan_t p={0}; assert(!fj_restore_journal_begin(&p));
    p.transaction_id[0]=0x25; p.old_keys_generation=3; p.old_hmac_generation=7;
    p.new_keys_generation=4; p.new_hmac_generation=8;
    memset(p.new_keys_digest,0x17,32); memset(p.new_hmac_digest,0x28,32);
    assert(!fj_restore_journal_commit() && !fj_restore_journal_finish());
    assert(fj_restore_journal_begin(&p));
    assert(fj_restore_journal_init()); check(FJ_RESTORE_PREPARED,&p);
    assert(!fj_restore_journal_begin(&p) && !fj_restore_journal_finish());
    assert(fj_restore_journal_abort());
    assert(fj_restore_journal_init()); check(FJ_RESTORE_CLEAN,NULL);
    assert(fj_restore_journal_begin(&p));
    assert(fj_restore_journal_commit());
    assert(fj_restore_journal_init()); check(FJ_RESTORE_COMMITTED,&p);
    assert(!fj_restore_journal_abort() && !fj_restore_journal_begin(&p));
    assert(!fj_restore_journal_finish());
    assert(fj_restore_journal_finalize());
    assert(fj_restore_journal_init()); check(FJ_RESTORE_FINALIZING,&p);
    assert(fj_restore_journal_finish());
    assert(fj_restore_journal_init()); check(FJ_RESTORE_CLEAN,NULL);
    assert(test_flash[start-1]==0x55 && test_flash[start+2u*FLASH_SECTOR_SIZE]==0xaa);
    /* Torn intent: do not expose any previous clean state as authoritative. */
    fail_program=true; assert(!fj_restore_journal_begin(&p)); fail_program=false;
    assert(!fj_restore_journal_init());
    fj_restore_phase_t phase; fj_restore_plan_t got;
    assert(!fj_restore_journal_read(&phase,&got));
    for(unsigned i=0;i<5;i++) torn_transition(i);
    puts("restore journal transitions and interrupted writes: ok");
}
