#include "hmac_config.h"
#include "hmac_store.h"
#include "flash_layout.h"
#include "crypto.h"
#include "hardware/sync.h"
#include <stddef.h>
#include <string.h>

#define CONFIG_MAGIC 0x464a4843u
#define CONFIG_VERSION 1u
typedef struct {
    uint32_t magic,version,generation,policy,root_mode,crc;
} config_record_t;
static uint8_t program[FLASH_PAGE_SIZE] __attribute__((aligned(4)));
static bool ready,configured;
static int active;
static uint32_t generation;
static fj_hmac_mode_t saved_policy;
static fj_hmac_root_mode_t saved_root_mode;

void fj_hmac_config_forget_ram(void) {
    fj_secure_zero(program,sizeof(program));
    ready=false; configured=false; active=-1; generation=0;
    saved_policy=FJ_HMAC_PIN_BUTTON; saved_root_mode=0;
}

static uint32_t crc32(const uint8_t *p,size_t n) {
    uint32_t c=0xffffffffu;
    while(n--) { c^=*p++; for (unsigned i=0;i<8;i++) c=(c>>1)^(0xedb88320u & (uint32_t)-(int32_t)(c&1)); }
    return c^0xffffffffu;
}
static const config_record_t *slot(unsigned n) {
    return (const void *)(XIP_BASE+FJ_HMAC_CONFIG_OFFSET+n*FLASH_SECTOR_SIZE);
}
static bool valid(const config_record_t *r) {
    return r->magic==CONFIG_MAGIC && r->version==CONFIG_VERSION &&
           r->policy<=FJ_HMAC_ARMED &&
           (r->root_mode==FJ_HMAC_ROOT_DEVELOPMENT || r->root_mode==FJ_HMAC_ROOT_OTP) &&
           r->crc==crc32((const uint8_t *)&r->version,offsetof(config_record_t,crc)-offsetof(config_record_t,version));
}
static bool erased(const void *address,size_t n) {
    const uint8_t *p=address; for (size_t i=0;i<n;i++) if(p[i]!=0xff) return false; return true;
}
bool fj_hmac_config_init(void) {
    fj_hmac_config_forget_ram();
    const config_record_t *a=slot(0),*b=slot(1);
    bool av=valid(a),bv=valid(b);
    if ((av && !bv && !erased(b,FLASH_SECTOR_SIZE)) ||
        (bv && !av && !erased(a,FLASH_SECTOR_SIZE))) return false;
    if (av && bv && a->generation==b->generation && memcmp(a,b,sizeof(*a))) return false;
    if (!av && !bv) {
        if (!erased(a,2u*FLASH_SECTOR_SIZE)) return false;
        ready=true; return true;
    }
    unsigned n=av && (!bv || (int32_t)(a->generation-b->generation)>0) ? 0u : 1u;
    const config_record_t *r=slot(n);
    active=(int)n; generation=r->generation; saved_policy=(fj_hmac_mode_t)r->policy;
    saved_root_mode=(fj_hmac_root_mode_t)r->root_mode;
    configured=true; ready=true; return true;
}
bool fj_hmac_config_get(fj_hmac_mode_t *policy,fj_hmac_root_mode_t *root_mode) {
    if (!ready || !configured || !policy || !root_mode) return false;
    *policy=saved_policy; *root_mode=saved_root_mode; return true;
}
bool fj_hmac_config_set(fj_hmac_mode_t policy,fj_hmac_root_mode_t root_mode,const uint8_t otp[32]) {
    if (!ready || policy<FJ_HMAC_PIN_BUTTON || policy>FJ_HMAC_ARMED ||
        (root_mode!=FJ_HMAC_ROOT_DEVELOPMENT && root_mode!=FJ_HMAC_ROOT_OTP) ||
        (configured && root_mode!=saved_root_mode)) return false;
    uint8_t root[32]={0};
    bool root_ok=fj_hmac_store_open_root(root_mode,otp,root);
    fj_secure_zero(root,sizeof(root));
    if (!root_ok) return false;
    if (configured && policy==saved_policy) return true;
    memset(program,0xff,sizeof(program)); config_record_t *r=(void *)program;
    r->magic=CONFIG_MAGIC; r->version=CONFIG_VERSION; r->generation=generation+1;
    r->policy=(uint32_t)policy; r->root_mode=(uint32_t)root_mode;
    r->crc=crc32((const uint8_t *)&r->version,offsetof(config_record_t,crc)-offsetof(config_record_t,version));
    unsigned target=active==0 ? 1u : 0u;
    uint32_t offset=FJ_HMAC_CONFIG_OFFSET+target*FLASH_SECTOR_SIZE;
    uint32_t ints=save_and_disable_interrupts();
    flash_range_erase(offset,FLASH_SECTOR_SIZE);
    flash_range_program(offset,program,sizeof(program));
    restore_interrupts(ints);
    if (!valid(slot(target)) || memcmp(slot(target),r,sizeof(*r))) { ready=false; return false; }
    active=(int)target; generation=r->generation; configured=true;
    saved_policy=policy; saved_root_mode=root_mode; return true;
}
