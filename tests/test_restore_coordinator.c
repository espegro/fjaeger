#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "hardware/flash.h"
#include "restore_coordinator.h"
_Alignas(4) uint8_t test_flash[PICO_FLASH_SIZE_BYTES];
void flash_range_erase(uint32_t offset,size_t n) { assert(offset+n<=sizeof(test_flash)); memset(test_flash+offset,0xff,n); }
void flash_range_program(uint32_t offset,const uint8_t *p,size_t n) { assert(offset+n<=sizeof(test_flash)); memcpy(test_flash+offset,p,n); }
typedef struct { bool keys_staged,hmac_staged; unsigned keys_active,hmac_active; unsigned calls, cut; } fake_t;
static bool hit(fake_t *f) { return ++f->calls!=f->cut; }
static bool sk(void *c,const fj_restore_plan_t *p) { (void)p; fake_t *f=c; f->keys_staged=true; return hit(f); }
static bool sh(void *c,const fj_restore_plan_t *p) { (void)p; fake_t *f=c; f->hmac_staged=true; return hit(f); }
static bool vs(void *c,const fj_restore_plan_t *p) { (void)p; fake_t *f=c; return f->keys_staged && f->hmac_staged && hit(f); }
static bool vo(void *c,const fj_restore_plan_t *p) { (void)p; fake_t *f=c; return f->keys_active==0 && f->hmac_active==0 && hit(f); }
static bool ds(void *c,const fj_restore_plan_t *p) { (void)p; fake_t *f=c; f->keys_staged=f->hmac_staged=false; return hit(f); }
static bool ak(void *c,const fj_restore_plan_t *p) { (void)p; fake_t *f=c; f->keys_active=1; return hit(f); }
static bool ah(void *c,const fj_restore_plan_t *p) { (void)p; fake_t *f=c; f->hmac_active=1; return hit(f); }
static bool vn(void *c,const fj_restore_plan_t *p) { (void)p; fake_t *f=c; return f->keys_active==1 && f->hmac_active==1 && hit(f); }
static bool dp(void *c,const fj_restore_plan_t *p) { (void)p; return hit(c); }
static fj_restore_ops_t ops(fake_t *f) { return (fj_restore_ops_t){f,sk,sh,vs,vo,ds,ak,ah,vn,dp}; }
static fj_restore_phase_t phase(void) { fj_restore_phase_t x; fj_restore_plan_t p; assert(fj_restore_journal_read(&x,&p)); return x; }
int main(void) {
    fj_restore_plan_t p={0}; p.transaction_id[0]=1;
    for(unsigned cut=1;cut<=11;cut++) {
        memset(test_flash,0xff,sizeof(test_flash)); assert(fj_restore_journal_init());
        fake_t f={.cut=cut}; fj_restore_ops_t o=ops(&f);
        assert(!fj_restore_execute(&o,&p));
        fj_restore_phase_t interrupted=phase(); assert(interrupted!=FJ_RESTORE_CLEAN);
        assert(fj_restore_journal_init()); f.cut=0; f.calls=0;
        assert(fj_restore_recover(&o)); assert(phase()==FJ_RESTORE_CLEAN);
        if(interrupted==FJ_RESTORE_PREPARED) assert(f.keys_active==0 && f.hmac_active==0);
        else assert(f.keys_active==1 && f.hmac_active==1);
    }
    /* Recovery itself may be interrupted after any operation and must be
     * safely repeatable. */
    for(unsigned committed=0;committed<=2;committed++) {
        unsigned count=committed==0 ? 3u : committed==1 ? 8u : 4u;
        for(unsigned cut=1;cut<=count;cut++) {
            memset(test_flash,0xff,sizeof(test_flash)); assert(fj_restore_journal_init());
            assert(fj_restore_journal_begin(&p));
            if(committed) assert(fj_restore_journal_commit());
            if(committed==2) assert(fj_restore_journal_finalize());
            fake_t retry={.keys_staged=true,.hmac_staged=true,.cut=cut};
            if(committed==2) retry.keys_active=retry.hmac_active=1;
            fj_restore_ops_t rops=ops(&retry);
            assert(!fj_restore_recover(&rops));
            fj_restore_phase_t interrupted=phase();
            assert(interrupted==FJ_RESTORE_PREPARED || interrupted==FJ_RESTORE_COMMITTED ||
                   interrupted==FJ_RESTORE_FINALIZING);
            assert(fj_restore_journal_init()); retry.cut=0; retry.calls=0;
            assert(fj_restore_recover(&rops)); assert(phase()==FJ_RESTORE_CLEAN);
            if(committed) assert(retry.keys_active==1 && retry.hmac_active==1);
            else assert(retry.keys_active==0 && retry.hmac_active==0);
        }
    }
    memset(test_flash,0xff,sizeof(test_flash)); assert(fj_restore_journal_init());
    fake_t f={.cut=1}; fj_restore_ops_t o=ops(&f);
    assert(!fj_restore_execute(&o,&p)); f.cut=0; f.keys_active=1;
    assert(!fj_restore_recover(&o)); assert(phase()==FJ_RESTORE_PREPARED);
    memset(test_flash,0xff,sizeof(test_flash)); assert(fj_restore_journal_init());
    f=(fake_t){.cut=5}; o=ops(&f); assert(!fj_restore_execute(&o,&p));
    assert(phase()==FJ_RESTORE_COMMITTED); f.cut=0; f.hmac_staged=false;
    assert(!fj_restore_recover(&o)); assert(phase()==FJ_RESTORE_COMMITTED);
    assert(!fj_restore_recover(NULL));
    puts("restore coordinator interruption and fail-closed tests: ok");
}
