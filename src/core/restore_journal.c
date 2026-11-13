#include "restore_journal.h"
#include "flash_layout.h"
#include "hardware/flash.h"
#include "hardware/sync.h"
#include <stddef.h>
#include <string.h>

/* Two sectors preceding the hmac-secret A/B sectors. */
#define JOURNAL_OFFSET FJ_RESTORE_JOURNAL_OFFSET
#define JOURNAL_MAGIC 0x464a524au
#define JOURNAL_VERSION 1u

typedef struct {
    uint32_t magic, version, generation, phase;
    fj_restore_plan_t plan;
    uint32_t crc;
} journal_record_t;
#define JOURNAL_PROGRAM_SIZE (((sizeof(journal_record_t)+FLASH_PAGE_SIZE-1u)/FLASH_PAGE_SIZE)*FLASH_PAGE_SIZE)
_Static_assert(JOURNAL_PROGRAM_SIZE <= FLASH_SECTOR_SIZE, "journal must fit in one sector");
_Static_assert(JOURNAL_OFFSET % FLASH_SECTOR_SIZE == 0, "journal must be sector aligned");
static uint8_t program[JOURNAL_PROGRAM_SIZE] __attribute__((aligned(4)));
static bool ready;
static int active = -1;
static uint32_t generation;
static fj_restore_phase_t phase;
static fj_restore_plan_t plan;

static uint32_t crc32_bytes(const uint8_t *p, size_t n) {
    uint32_t crc=0xffffffffu;
    while(n--) { crc^=*p++; for(unsigned i=0;i<8;i++) crc=(crc>>1)^(0xedb88320u & (uint32_t)-(int32_t)(crc&1)); }
    return crc ^ 0xffffffffu;
}
static const journal_record_t *slot(unsigned n) {
    return (const journal_record_t *)(XIP_BASE + JOURNAL_OFFSET + n*FLASH_SECTOR_SIZE);
}
static bool all_zero(const void *p,size_t n) {
    const uint8_t *b=p; uint8_t v=0; for(size_t i=0;i<n;i++) v|=b[i]; return v==0;
}
static bool valid(const journal_record_t *r) {
    if(r->magic!=JOURNAL_MAGIC || r->version!=JOURNAL_VERSION || r->phase>FJ_RESTORE_WIPING) return false;
    if ((r->phase==FJ_RESTORE_CLEAN || r->phase==FJ_RESTORE_WIPING) ?
        !all_zero(&r->plan,sizeof(r->plan)) : all_zero(r->plan.transaction_id,sizeof(r->plan.transaction_id))) return false;
    return r->crc == crc32_bytes((const uint8_t *)&r->version,
                                 (size_t)((const uint8_t *)&r->crc-(const uint8_t *)&r->version));
}
static bool erased(const uint8_t *p,size_t n) {
    for(size_t i=0;i<n;i++) if(p[i]!=0xff) return false;
    return true;
}
bool fj_restore_journal_init(void) {
    ready=false; active=-1; generation=0; phase=FJ_RESTORE_CLEAN; memset(&plan,0,sizeof(plan));
    const journal_record_t *a=slot(0),*b=slot(1);
    if ((a->magic==JOURNAL_MAGIC && a->version!=JOURNAL_VERSION) ||
        (b->magic==JOURNAL_MAGIC && b->version!=JOURNAL_VERSION)) return false;
    bool av=valid(a),bv=valid(b);
    /* An invalid non-erased peer may be a torn newer decision. Do not guess
     * which transaction state is authoritative; require explicit recovery. */
    if (av && !bv && !erased((const uint8_t *)b,FLASH_SECTOR_SIZE)) return false;
    if (bv && !av && !erased((const uint8_t *)a,FLASH_SECTOR_SIZE)) return false;
    if (av && bv && a->generation==b->generation && memcmp(a,b,sizeof(*a))!=0) return false;
    if(av || bv) {
        unsigned n=av && (!bv || (int32_t)(a->generation-b->generation)>0) ? 0u : 1u;
        const journal_record_t *r=slot(n); active=(int)n; generation=r->generation;
        phase=(fj_restore_phase_t)r->phase; plan=r->plan; ready=true; return true;
    }
    if(!erased((const uint8_t *)a,2u*FLASH_SECTOR_SIZE)) return false;
    ready=true; return true;
}
bool fj_restore_journal_read(fj_restore_phase_t *out_phase, fj_restore_plan_t *out_plan) {
    if(!ready || !out_phase || !out_plan) return false;
    *out_phase=phase; *out_plan=plan; return true;
}
bool fj_restore_journal_authorizes_commit(const fj_restore_plan_t *candidate) {
    return ready && candidate && phase==FJ_RESTORE_COMMITTED &&
           memcmp(&plan,candidate,sizeof(plan))==0;
}
bool fj_restore_journal_authorizes_finalize(const fj_restore_plan_t *candidate) {
    return ready && candidate && phase==FJ_RESTORE_FINALIZING &&
           memcmp(&plan,candidate,sizeof(plan))==0;
}
static bool commit_record(fj_restore_phase_t next, const fj_restore_plan_t *next_plan) {
    if(!ready || !next_plan) return false;
    unsigned target=active==0 ? 1u : 0u;
    memset(program,0xff,sizeof(program)); journal_record_t *r=(void *)program;
    r->magic=JOURNAL_MAGIC; r->version=JOURNAL_VERSION; r->generation=generation+1;
    r->phase=next; r->plan=*next_plan;
    r->crc=crc32_bytes((const uint8_t *)&r->version,
                       (size_t)((const uint8_t *)&r->crc-(const uint8_t *)&r->version));
    uint32_t ints=save_and_disable_interrupts();
    flash_range_erase(JOURNAL_OFFSET+target*FLASH_SECTOR_SIZE,FLASH_SECTOR_SIZE);
    flash_range_program(JOURNAL_OFFSET+target*FLASH_SECTOR_SIZE,program,sizeof(program));
    restore_interrupts(ints);
    if(!valid(slot(target))) { ready=false; return false; }
    active=(int)target; generation=r->generation; phase=next; plan=*next_plan; return true;
}
bool fj_restore_journal_begin(const fj_restore_plan_t *next) {
    if(!ready || phase!=FJ_RESTORE_CLEAN || !next || all_zero(next->transaction_id,sizeof(next->transaction_id))) return false;
    return commit_record(FJ_RESTORE_PREPARED,next);
}
bool fj_restore_journal_commit(void) {
    if(!ready || phase!=FJ_RESTORE_PREPARED) return false;
    return commit_record(FJ_RESTORE_COMMITTED,&plan);
}
bool fj_restore_journal_finalize(void) {
    if(!ready || phase!=FJ_RESTORE_COMMITTED) return false;
    return commit_record(FJ_RESTORE_FINALIZING,&plan);
}
static bool clear_journal(void) {
    const fj_restore_plan_t empty={0}; return commit_record(FJ_RESTORE_CLEAN,&empty);
}
bool fj_restore_journal_abort(void) {
    return ready && phase==FJ_RESTORE_PREPARED && clear_journal();
}
bool fj_restore_journal_finish(void) {
    return ready && phase==FJ_RESTORE_FINALIZING && clear_journal();
}
bool fj_restore_journal_begin_wipe(void) {
    const fj_restore_plan_t empty={0};
    return ready && phase==FJ_RESTORE_CLEAN && commit_record(FJ_RESTORE_WIPING,&empty);
}
bool fj_restore_journal_finish_wipe(void) {
    return ready && phase==FJ_RESTORE_WIPING && clear_journal();
}
