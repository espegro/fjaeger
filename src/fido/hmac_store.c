#include "hmac_store.h"
#include "hmac_backup.h"
#include "crypto.h"
#include "flash_layout.h"
#include "hardware/flash.h"
#include "hardware/sync.h"
#include <stdint.h>
#include <stddef.h>
#include <string.h>

/* Two dedicated 4 KiB sectors immediately before the v17 key store. Do not
 * reuse the device CWK or the normal FIDO credential table. */
#define HMAC_SLOT_SIZE FLASH_SECTOR_SIZE
#define HMAC_FLASH_OFFSET FJ_HMAC_STORE_OFFSET
#define HMAC_STORE_MAGIC 0x464a4853u
#define HMAC_STORE_VERSION 3u

typedef struct { uint8_t used; fj_hmac_credential_t credential; } hmac_entry_t;
typedef struct {
    uint32_t magic, version, generation, payload_size;
    uint8_t root_configured;
    uint8_t erase_previous;
    fj_hmac_root_record_t root;
    hmac_entry_t entries[FJ_HMAC_STORE_CAPACITY];
    uint32_t crc;
} hmac_record_t;
#define HMAC_PROGRAM_SIZE (((sizeof(hmac_record_t) + FLASH_PAGE_SIZE - 1u) / FLASH_PAGE_SIZE) * FLASH_PAGE_SIZE)
_Static_assert(HMAC_PROGRAM_SIZE <= HMAC_SLOT_SIZE, "hmac store exceeds a flash sector");
_Static_assert(HMAC_FLASH_OFFSET % FLASH_SECTOR_SIZE == 0, "hmac store must be sector aligned");

static hmac_entry_t entries[FJ_HMAC_STORE_CAPACITY];
static fj_hmac_root_record_t root_record;
static bool root_configured;
static uint8_t program_buffer[HMAC_PROGRAM_SIZE] __attribute__((aligned(4)));
static bool ready;
static int active = -1;
static uint32_t generation;

bool fj_hmac_restore_generation(uint32_t *out) {
    if (!ready || !out) return false;
    *out=generation; return true;
}

static uint32_t crc_bytes(const uint8_t *p, size_t n) {
    uint32_t crc = 0xffffffffu;
    while (n--) { crc ^= *p++; for (unsigned i=0;i<8;i++) crc=(crc>>1)^(0xedb88320u & (uint32_t)-(int32_t)(crc&1)); }
    return crc ^ 0xffffffffu;
}
static const hmac_record_t *slot(unsigned n) {
    return (const hmac_record_t *)(XIP_BASE + HMAC_FLASH_OFFSET + n * HMAC_SLOT_SIZE);
}
static bool valid(const hmac_record_t *r) {
    if (r->magic != HMAC_STORE_MAGIC || r->version != HMAC_STORE_VERSION ||
        r->payload_size != sizeof(r->root_configured) + sizeof(r->erase_previous) + sizeof(r->root) + sizeof(r->entries) ||
        r->root_configured > 1 || r->erase_previous > 1) return false;
    const uint8_t *begin=(const uint8_t *)&r->version, *end=(const uint8_t *)&r->crc;
    if (r->crc != crc_bytes(begin, (size_t)(end-begin))) return false;
    if (r->root_configured && (r->root.version != 1 ||
        (r->root.mode != FJ_HMAC_ROOT_DEVELOPMENT && r->root.mode != FJ_HMAC_ROOT_OTP))) return false;
    for (size_t i=0; i<FJ_HMAC_STORE_CAPACITY; i++)
        if (r->entries[i].used > 1 || (r->entries[i].used && !r->root_configured)) return false;
    return true;
}
static bool is_erased(const uint8_t *p, size_t n) {
    for (size_t i=0; i<n; i++) if (p[i] != 0xff) return false;
    return true;
}
static bool erase_slot(unsigned n) {
    uint32_t interrupts=save_and_disable_interrupts();
    flash_range_erase(HMAC_FLASH_OFFSET+n*HMAC_SLOT_SIZE,HMAC_SLOT_SIZE);
    restore_interrupts(interrupts);
    return is_erased((const uint8_t *)slot(n),HMAC_SLOT_SIZE);
}
bool fj_hmac_store_init(void) {
    ready=false; active=-1; generation=0; root_configured=false;
    fj_secure_zero(&root_record,sizeof(root_record)); fj_secure_zero(entries,sizeof(entries));
    const hmac_record_t *a=slot(0), *b=slot(1);
    /* Never silently fall back when a future, recognized store format exists. */
    if ((a->magic == HMAC_STORE_MAGIC && a->version != HMAC_STORE_VERSION) ||
        (b->magic == HMAC_STORE_MAGIC && b->version != HMAC_STORE_VERSION)) return false;
    bool av=valid(a), bv=valid(b);
    if (av || bv) {
        unsigned selected = av && (!bv || (int32_t)(a->generation-b->generation)>0) ? 0u : 1u;
        const hmac_record_t *r=slot(selected);
        memcpy(entries,r->entries,sizeof(entries)); root_record=r->root;
        root_configured=r->root_configured != 0; active=(int)selected; generation=r->generation;
        /* Complete a previously committed wipe or deletion before allowing
         * access or new writes. The marker belongs to the validated record. */
        if (r->erase_previous && !is_erased((const uint8_t *)slot(1u-selected),HMAC_SLOT_SIZE) &&
            !erase_slot(1u-selected)) return false;
        ready=true; return true;
    }
    /* Corruption, a partial first write, or an unknown version is not a blank
     * store; do not silently replace or downgrade it. */
    if (!is_erased((const uint8_t *)a,2u*HMAC_SLOT_SIZE)) return false;
    ready=true; return true;
}
static bool commit(bool erase_previous) {
    if (!ready) return false;
    unsigned target=active==0 ? 1u : 0u;
    memset(program_buffer,0xff,sizeof(program_buffer));
    hmac_record_t *r=(void *)program_buffer;
    r->magic=HMAC_STORE_MAGIC; r->version=HMAC_STORE_VERSION;
    r->generation=generation+1;
    r->payload_size=sizeof(r->root_configured)+sizeof(r->erase_previous)+sizeof(r->root)+sizeof(r->entries);
    r->root_configured=root_configured ? 1 : 0;
    r->erase_previous=erase_previous ? 1 : 0;
    r->root=root_record;
    memcpy(r->entries,entries,sizeof(entries));
    r->crc=crc_bytes((const uint8_t *)&r->version,(size_t)((const uint8_t *)&r->crc-(const uint8_t *)&r->version));
    uint32_t interrupts=save_and_disable_interrupts();
    flash_range_erase(HMAC_FLASH_OFFSET+target*HMAC_SLOT_SIZE,HMAC_SLOT_SIZE);
    flash_range_program(HMAC_FLASH_OFFSET+target*HMAC_SLOT_SIZE,program_buffer,sizeof(program_buffer));
    restore_interrupts(interrupts);
    if (!valid(slot(target))) return false;
    active=(int)target; generation=r->generation;
    return true;
}
static int find(const uint8_t id[16]) {
    for (unsigned i=0;i<FJ_HMAC_STORE_CAPACITY;i++)
        if (entries[i].used && memcmp(entries[i].credential.credential_id,id,16)==0) return (int)i;
    return -1;
}
bool fj_hmac_store_id_exists(void *ctx,const uint8_t id[16]) {
    (void)ctx;
    return !ready || !id || find(id)>=0;
}
bool fj_hmac_store_legacy_backup_safe(void) { return ready && !root_configured; }
bool fj_hmac_store_provision_root(const fj_hmac_root_record_t *record,
                                  const uint8_t otp[32]) {
    if (!ready || !record || root_configured || record->version != 1 ||
        (record->mode != FJ_HMAC_ROOT_DEVELOPMENT && record->mode != FJ_HMAC_ROOT_OTP)) return false;
    uint8_t root[32];
    bool valid_root = fj_hmac_root_open(record, (fj_hmac_root_mode_t)record->mode, otp, root);
    fj_secure_zero(root, sizeof(root));
    if (!valid_root) return false;
    root_record=*record; root_configured=true;
    if (commit(false)) return true;
    fj_secure_zero(&root_record,sizeof(root_record)); root_configured=false; return false;
}
bool fj_hmac_store_open_root(fj_hmac_root_mode_t expected_mode,
                             const uint8_t otp[32], uint8_t root[32]) {
    if (!root) return false;
    if (!ready || !root_configured) { fj_secure_zero(root,32); return false; }
    return fj_hmac_root_open(&root_record,expected_mode,otp,root);
}
bool fj_hmac_store_get(const uint8_t id[16], fj_hmac_credential_t *out) {
    if (!ready || !id || !out) return false;
    int n=find(id); if (n<0) return false;
    *out=entries[n].credential; return true;
}
bool fj_hmac_store_list(fj_hmac_credential_info_t *out,size_t capacity,size_t *count) {
    if (!ready || !count || (!out && capacity)) return false;
    size_t n=0;
    for (unsigned i=0;i<FJ_HMAC_STORE_CAPACITY;i++) if (entries[i].used) n++;
    if (capacity<n) return false;
    n=0;
    for (unsigned i=0;i<FJ_HMAC_STORE_CAPACITY;i++) if (entries[i].used) {
        memcpy(out[n].credential_id,entries[i].credential.credential_id,16);
        memcpy(out[n].rp_id_hash,entries[i].credential.rp_id_hash,32); n++;
    }
    *count=n; return true;
}
bool fj_hmac_store_put(const fj_hmac_credential_t *credential) {
    if (!ready || !root_configured || !credential || find(credential->credential_id)>=0) return false;
    unsigned i=0; while (i<FJ_HMAC_STORE_CAPACITY && entries[i].used) i++;
    if (i==FJ_HMAC_STORE_CAPACITY) return false;
    entries[i].credential=*credential; entries[i].used=1;
    if (commit(false)) return true;
    fj_secure_zero(&entries[i],sizeof(entries[i])); return false;
}
bool fj_hmac_store_remove(const uint8_t id[16]) {
    if (!ready || !id) return false;
    int n=find(id); if (n<0) return false;
    hmac_entry_t previous=entries[n];
    fj_secure_zero(&entries[n],sizeof(entries[n]));
    if (!commit(true)) {
        entries[n]=previous;
        fj_secure_zero(&previous,sizeof(previous));
        return false;
    }
    fj_secure_zero(&previous,sizeof(previous));
    /* Do not report success until the old ciphertext copy is erased. If
     * interrupted, the new record makes the next init finish the erase. */
    if (!erase_slot(active == 0 ? 1u : 0u)) { ready=false; return false; }
    return true;
}
bool fj_hmac_store_wipe(void) {
    if (!ready) return false;
    /* Save the RAM snapshot in a temporary static workspace: the entries are
     * already encrypted and the snapshot is scrubbed before returning. */
    static hmac_entry_t previous[FJ_HMAC_STORE_CAPACITY];
    fj_hmac_root_record_t previous_root=root_record;
    bool had_root=root_configured;
    memcpy(previous,entries,sizeof(entries));
    fj_secure_zero(entries,sizeof(entries));
    fj_secure_zero(&root_record,sizeof(root_record)); root_configured=false;
    if (!commit(true)) {
        memcpy(entries,previous,sizeof(entries)); root_record=previous_root;
        root_configured=had_root;
        fj_secure_zero(previous,sizeof(previous));
        fj_secure_zero(&previous_root,sizeof(previous_root));
        return false;
    }
    fj_secure_zero(previous,sizeof(previous));
    fj_secure_zero(&previous_root,sizeof(previous_root));
    /* Keep the tombstone until a later provision replaces it. */
    if (!erase_slot(active == 0 ? 1u : 0u)) { ready=false; return false; }
    return true;
}

bool fj_hmac_store_export(fj_hmac_root_mode_t expected_mode,
                          const uint8_t otp[32], fj_hmac_snapshot_t *out) {
    if (!out) return false;
    fj_secure_zero(out,sizeof(*out));
    if (!fj_hmac_store_open_root(expected_mode,otp,out->root)) return false;
    for (unsigned i=0;i<FJ_HMAC_STORE_CAPACITY;i++) {
        out->entries[i].used=entries[i].used;
        if (entries[i].used) out->entries[i].credential=entries[i].credential;
    }
    if (fj_hmac_snapshot_valid(out)) return true;
    fj_secure_zero(out,sizeof(*out)); return false;
}

bool fj_hmac_store_restore_empty(const fj_hmac_snapshot_t *snapshot,
                                 const fj_hmac_root_record_t *new_root,
                                 const uint8_t otp[32]) {
    if (!ready || root_configured || !snapshot || !new_root ||
        !fj_hmac_snapshot_valid(snapshot)) return false;
    uint8_t unwrapped[32] = {0};
    bool ok=fj_hmac_root_open(new_root,(fj_hmac_root_mode_t)new_root->mode,otp,unwrapped) &&
            fj_ct_equal(unwrapped,snapshot->root,32);
    fj_secure_zero(unwrapped,sizeof(unwrapped));
    if (!ok) return false;
    root_record=*new_root; root_configured=true;
    for (unsigned i=0;i<FJ_HMAC_STORE_CAPACITY;i++) {
        entries[i].used=snapshot->entries[i].used;
        entries[i].credential=snapshot->entries[i].credential;
    }
    if (commit(false)) return true;
    fj_secure_zero(&root_record,sizeof(root_record)); root_configured=false;
    fj_secure_zero(entries,sizeof(entries)); return false;
}

/* Dedicated staging sector: the normal loader never examines it. Retaining
 * this copy across activation is essential to repeat recovery after a crash. */
#define HMAC_STAGE_MAGIC 0x464a4854u
typedef struct {
    uint32_t magic, version;
    uint8_t transaction_id[16];
    hmac_record_t image;
} hmac_stage_t;
#define HMAC_STAGE_PROGRAM_SIZE (((sizeof(hmac_stage_t) + FLASH_PAGE_SIZE - 1u) / FLASH_PAGE_SIZE) * FLASH_PAGE_SIZE)
_Static_assert(HMAC_STAGE_PROGRAM_SIZE <= FLASH_SECTOR_SIZE, "hmac stage exceeds sector");
static uint8_t stage_buffer[HMAC_STAGE_PROGRAM_SIZE] __attribute__((aligned(4)));

void fj_hmac_store_forget_ram(void) {
    fj_secure_zero(entries,sizeof(entries));
    fj_secure_zero(&root_record,sizeof(root_record));
    fj_secure_zero(program_buffer,sizeof(program_buffer));
    fj_secure_zero(stage_buffer,sizeof(stage_buffer));
    root_configured=false; ready=false; active=-1; generation=0;
}

static bool nonzero_id(const uint8_t id[16]) {
    uint8_t any=0;
    for (unsigned i=0;i<16;i++) any|=id[i];
    return any!=0;
}
static bool stage_build(const fj_hmac_snapshot_t *snapshot,
                        const fj_hmac_root_record_t *root, const uint8_t otp[32],
                        const fj_restore_plan_t *plan) {
    if (!ready || !snapshot || !root || !plan || !nonzero_id(plan->transaction_id) ||
        generation!=plan->old_hmac_generation ||
        plan->new_hmac_generation!=plan->old_hmac_generation+1u ||
        !fj_hmac_snapshot_valid(snapshot)) return false;
    uint8_t unwrapped[32]={0};
    bool ok=fj_hmac_root_open(root,(fj_hmac_root_mode_t)root->mode,otp,unwrapped) &&
            fj_ct_equal(unwrapped,snapshot->root,sizeof(unwrapped));
    fj_secure_zero(unwrapped,sizeof(unwrapped));
    if (!ok) return false;
    memset(stage_buffer,0,sizeof(stage_buffer));
    hmac_stage_t *stage=(void *)stage_buffer;
    stage->magic=HMAC_STAGE_MAGIC; stage->version=1;
    memcpy(stage->transaction_id,plan->transaction_id,16);
    hmac_record_t *r=&stage->image;
    r->magic=HMAC_STORE_MAGIC; r->version=HMAC_STORE_VERSION;
    r->generation=plan->new_hmac_generation;
    r->payload_size=sizeof(r->root_configured)+sizeof(r->erase_previous)+sizeof(r->root)+sizeof(r->entries);
    r->root_configured=1; r->root=*root;
    for (unsigned i=0;i<FJ_HMAC_STORE_CAPACITY;i++) {
        r->entries[i].used=snapshot->entries[i].used;
        if (r->entries[i].used) r->entries[i].credential=snapshot->entries[i].credential;
    }
    r->crc=crc_bytes((const uint8_t *)&r->version,(size_t)((const uint8_t *)&r->crc-(const uint8_t *)&r->version));
    return true;
}
bool fj_hmac_stage_digest(const fj_hmac_snapshot_t *snapshot,
                          const fj_hmac_root_record_t *root, const uint8_t otp[32],
                          const fj_restore_plan_t *plan, uint8_t digest[32]) {
    if (!digest) return false;
    memset(digest,0,32);
    bool ok=stage_build(snapshot,root,otp,plan);
    if (ok) fj_sha256(stage_buffer,sizeof(hmac_stage_t),digest);
    fj_secure_zero(stage_buffer,sizeof(stage_buffer));
    return ok;
}
bool fj_hmac_stage_verify(const fj_restore_plan_t *plan) {
    if (!plan || !nonzero_id(plan->transaction_id) ||
        plan->new_hmac_generation!=plan->old_hmac_generation+1u) return false;
    const hmac_stage_t *stage=(const void *)(XIP_BASE+FJ_HMAC_STAGE_OFFSET);
    if (stage->magic!=HMAC_STAGE_MAGIC || stage->version!=1 ||
        memcmp(stage->transaction_id,plan->transaction_id,16)!=0 ||
        stage->image.generation!=plan->new_hmac_generation || !valid(&stage->image)) return false;
    uint8_t digest[32];
    fj_sha256((const uint8_t *)stage,sizeof(*stage),digest);
    bool ok=fj_ct_equal(digest,plan->new_hmac_digest,sizeof(digest));
    fj_secure_zero(digest,sizeof(digest));
    return ok;
}
bool fj_hmac_stage_write(const fj_hmac_snapshot_t *snapshot,
                         const fj_hmac_root_record_t *root, const uint8_t otp[32],
                         const fj_restore_plan_t *plan) {
    if (!plan) return false;
    /* Never overwrite a prior transaction or a torn stage automatically. */
    if (!is_erased((const uint8_t *)(XIP_BASE+FJ_HMAC_STAGE_OFFSET),FLASH_SECTOR_SIZE))
        return fj_hmac_stage_verify(plan);
    bool ok=stage_build(snapshot,root,otp,plan);
    uint8_t digest[32]={0};
    if (ok) {
        fj_sha256(stage_buffer,sizeof(hmac_stage_t),digest);
        ok=fj_ct_equal(digest,plan->new_hmac_digest,sizeof(digest));
    }
    if (ok) {
        uint32_t interrupts=save_and_disable_interrupts();
        flash_range_program(FJ_HMAC_STAGE_OFFSET,stage_buffer,sizeof(stage_buffer));
        restore_interrupts(interrupts);
        ok=fj_hmac_stage_verify(plan);
    }
    fj_secure_zero(digest,sizeof(digest));
    fj_secure_zero(stage_buffer,sizeof(stage_buffer));
    return ok;
}
bool fj_hmac_stage_activate(const fj_restore_plan_t *plan) {
    if (!fj_restore_journal_authorizes_commit(plan) || !fj_hmac_stage_verify(plan)) return false;
    const hmac_stage_t *staged=(const void *)(XIP_BASE+FJ_HMAC_STAGE_OFFSET);
    const hmac_record_t *a=slot(0), *b=slot(1);
    bool av=valid(a), bv=valid(b);
    if (av && a->generation==plan->new_hmac_generation) {
        bool same=memcmp(a,&staged->image,sizeof(*a))==0; ready=false; return same;
    }
    if (bv && b->generation==plan->new_hmac_generation) {
        bool same=memcmp(b,&staged->image,sizeof(*b))==0; ready=false; return same;
    }
    unsigned target;
    if (!av && !bv) {
        bool ae=is_erased((const uint8_t *)a,HMAC_SLOT_SIZE);
        bool be=is_erased((const uint8_t *)b,HMAC_SLOT_SIZE);
        if (plan->old_hmac_generation!=0 || (!ae && !be)) return false;
        /* Retry a torn first write in its original slot. */
        target=ae && !be ? 1u : 0u;
    } else {
        unsigned old=av && (!bv || (int32_t)(a->generation-b->generation)>0) ? 0u : 1u;
        if (slot(old)->generation!=plan->old_hmac_generation) return false;
        target=1u-old;
    }
    memset(program_buffer,0xff,sizeof(program_buffer));
    memcpy(program_buffer,&staged->image,sizeof(staged->image));
    ready=false;
    uint32_t ints=save_and_disable_interrupts();
    flash_range_erase(HMAC_FLASH_OFFSET+target*HMAC_SLOT_SIZE,HMAC_SLOT_SIZE);
    flash_range_program(HMAC_FLASH_OFFSET+target*HMAC_SLOT_SIZE,program_buffer,sizeof(program_buffer));
    restore_interrupts(ints);
    bool ok=valid(slot(target)) && memcmp(slot(target),&staged->image,sizeof(staged->image))==0;
    fj_secure_zero(program_buffer,sizeof(program_buffer));
    return ok;
}
static const hmac_record_t *restore_selected(void) {
    const hmac_record_t *a=slot(0), *b=slot(1);
    bool av=valid(a), bv=valid(b);
    if (!av && !bv) return NULL;
    if (av && bv && a->generation==b->generation && memcmp(a,b,sizeof(*a))!=0) return NULL;
    return av && (!bv || (int32_t)(a->generation-b->generation)>0) ? a : b;
}
bool fj_hmac_restore_old_active(const fj_restore_plan_t *plan) {
    if (!plan) return false;
    const hmac_record_t *selected=restore_selected();
    if (selected) return selected->generation==plan->old_hmac_generation;
    return plan->old_hmac_generation==0 &&
           is_erased((const uint8_t *)slot(0),2u*HMAC_SLOT_SIZE);
}
bool fj_hmac_stage_is_active(const fj_restore_plan_t *plan) {
    if (!fj_hmac_stage_verify(plan)) return false;
    const hmac_stage_t *staged=(const void *)(XIP_BASE+FJ_HMAC_STAGE_OFFSET);
    const hmac_record_t *selected=restore_selected();
    return selected && selected->generation==plan->new_hmac_generation &&
           memcmp(selected,&staged->image,sizeof(*selected))==0;
}
bool fj_hmac_restore_new_active(const fj_restore_plan_t *plan) {
    if (!plan || !nonzero_id(plan->transaction_id) ||
        plan->new_hmac_generation!=plan->old_hmac_generation+1u) return false;
    const hmac_record_t *selected=restore_selected();
    if (!selected || selected->generation!=plan->new_hmac_generation) return false;
    memset(stage_buffer,0,sizeof(stage_buffer));
    hmac_stage_t *stage=(void *)stage_buffer;
    stage->magic=HMAC_STAGE_MAGIC; stage->version=1;
    memcpy(stage->transaction_id,plan->transaction_id,16);
    memcpy(&stage->image,selected,sizeof(stage->image));
    uint8_t digest[32]; fj_sha256(stage_buffer,sizeof(*stage),digest);
    bool ok=fj_ct_equal(digest,plan->new_hmac_digest,32);
    fj_secure_zero(digest,sizeof(digest)); fj_secure_zero(stage_buffer,sizeof(stage_buffer));
    return ok;
}
bool fj_hmac_restore_discard_previous(const fj_restore_plan_t *plan) {
    if (!fj_restore_journal_authorizes_finalize(plan) || !fj_hmac_restore_new_active(plan)) return false;
    const hmac_record_t *selected=restore_selected();
    if (!selected) return false;
    unsigned inactive=selected==slot(0) ? 1u : 0u;
    if (!is_erased((const uint8_t *)slot(inactive),HMAC_SLOT_SIZE) && !erase_slot(inactive)) return false;
    return fj_hmac_restore_new_active(plan);
}
bool fj_hmac_stage_discard(void) {
    if (is_erased((const uint8_t *)(XIP_BASE+FJ_HMAC_STAGE_OFFSET),FLASH_SECTOR_SIZE)) return true;
    uint32_t interrupts=save_and_disable_interrupts();
    flash_range_erase(FJ_HMAC_STAGE_OFFSET,FLASH_SECTOR_SIZE);
    restore_interrupts(interrupts);
    return is_erased((const uint8_t *)(XIP_BASE+FJ_HMAC_STAGE_OFFSET),FLASH_SECTOR_SIZE);
}
