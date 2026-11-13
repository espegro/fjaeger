#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "hardware/flash.h"
#include "flash_layout.h"
#include "hmac_config.h"
#include "hmac_store.h"
#include "hmac_runtime.h"
#include "state.h"

_Alignas(4) uint8_t test_flash[PICO_FLASH_SIZE_BYTES];
static bool torn_program;
static fj_state_t test_state=FJ_STATE_LOCKED;
static bool pin_configured;
fj_state_t fj_state_get(void) { return test_state; }
bool fj_state_ctap2_pin_configured(void) { return pin_configured; }
void fj_random(void *p,size_t n) { memset(p,0x42,n); }
void flash_range_erase(uint32_t off,size_t n) { assert(off+n<=sizeof(test_flash)); memset(test_flash+off,0xff,n); }
void flash_range_program(uint32_t off,const uint8_t *p,size_t n) {
    assert(off+n<=sizeof(test_flash)); if(torn_program) n=12; memcpy(test_flash+off,p,n);
}
int main(void) {
    memset(test_flash,0xff,sizeof(test_flash));
    assert(fj_hmac_runtime_init(NULL,false,0));
    assert(!fj_hmac_runtime_provision_development(true,false,0));
    test_state=FJ_STATE_UNLOCKED;
    assert(!fj_hmac_runtime_provision_development(true,false,0));
    pin_configured=true;
    assert(!fj_hmac_runtime_provision_development(false,false,0));
    assert(fj_hmac_runtime_provision_development(true,false,0));
    assert(fj_hmac_runtime_enabled());
    fj_hmac_runtime_forget();
    memset(test_flash,0xff,sizeof(test_flash));
    assert(fj_hmac_runtime_init(NULL,false,0));
    /* Simulate power loss after the root write but before configuration. */
    uint8_t resume_root[32]={9},resume_salt[16]={8},resume_nonce[12]={7},opened[32];
    fj_hmac_root_record_t resume_record;
    assert(fj_hmac_root_create(&resume_record,FJ_HMAC_ROOT_DEVELOPMENT,
                               resume_root,NULL,resume_salt,resume_nonce));
    assert(fj_hmac_store_provision_root(&resume_record,NULL));
    torn_program=true;
    assert(!fj_hmac_runtime_provision_development(true,false,1));
    torn_program=false;
    assert(!fj_hmac_runtime_enabled());
    assert(!fj_hmac_config_init()); /* torn configuration fails closed */
    assert(fj_hmac_store_init());
    assert(fj_hmac_store_open_root(FJ_HMAC_ROOT_DEVELOPMENT,NULL,opened));
    assert(memcmp(opened,resume_root,sizeof(opened))==0);
    /* Simulate recovery of the configuration area, preserving the root. */
    memset(test_flash+FJ_HMAC_CONFIG_OFFSET,0xff,2u*FLASH_SECTOR_SIZE);
    assert(fj_hmac_runtime_provision_development(true,false,1));
    assert(fj_hmac_runtime_enabled());
    assert(fj_hmac_store_open_root(FJ_HMAC_ROOT_DEVELOPMENT,NULL,opened));
    assert(memcmp(opened,resume_root,sizeof(opened))==0);
    assert(fj_hmac_runtime_policy()->mode==FJ_HMAC_PIN_BUTTON);
    assert(!fj_hmac_runtime_provision_development(true,false,2));
    fj_hmac_runtime_forget();
    memset(test_flash,0xff,sizeof(test_flash));
    test_state=FJ_STATE_LOCKED; pin_configured=false;
    test_flash[FJ_HMAC_CONFIG_OFFSET-1]=0x71;
    test_flash[FJ_KEYS_STAGE_OFFSET]=0x72;
    assert(fj_hmac_store_init()); assert(fj_hmac_config_init());
    fj_hmac_mode_t policy; fj_hmac_root_mode_t mode;
    assert(!fj_hmac_config_get(&policy,&mode));
    uint8_t otp[32]={1},wrong[32]={2},root[32]={3},salt[16]={4},nonce[12]={5};
    assert(fj_hmac_runtime_init(otp,false,0));
    assert(!fj_hmac_runtime_enabled());
    assert(!fj_hmac_config_set(FJ_HMAC_AUTO,FJ_HMAC_ROOT_OTP,otp));
    fj_hmac_root_record_t wrapped;
    assert(fj_hmac_root_create(&wrapped,FJ_HMAC_ROOT_OTP,root,otp,salt,nonce));
    assert(fj_hmac_store_provision_root(&wrapped,otp));
    test_state=FJ_STATE_UNLOCKED; pin_configured=true;
    assert(!fj_hmac_runtime_provision_development(true,false,0));
    assert(fj_hmac_store_open_root(FJ_HMAC_ROOT_OTP,otp,opened));
    assert(memcmp(opened,root,sizeof(root))==0);
    test_state=FJ_STATE_LOCKED; pin_configured=false;
    assert(!fj_hmac_config_set(FJ_HMAC_AUTO,FJ_HMAC_ROOT_OTP,wrong));
    assert(!fj_hmac_config_set((fj_hmac_mode_t)99,FJ_HMAC_ROOT_OTP,otp));
    assert(fj_hmac_config_set(FJ_HMAC_PIN_BUTTON,FJ_HMAC_ROOT_OTP,otp));
    assert(fj_hmac_config_init() && fj_hmac_config_get(&policy,&mode));
    assert(policy==FJ_HMAC_PIN_BUTTON && mode==FJ_HMAC_ROOT_OTP);
    assert(!fj_hmac_config_set(FJ_HMAC_AUTO,FJ_HMAC_ROOT_DEVELOPMENT,NULL));
    assert(fj_hmac_config_set(FJ_HMAC_ARMED,FJ_HMAC_ROOT_OTP,otp));
    assert(fj_hmac_config_init() && fj_hmac_config_get(&policy,&mode));
    assert(policy==FJ_HMAC_ARMED && mode==FJ_HMAC_ROOT_OTP);
    fj_hmac_config_forget_ram();
    assert(!fj_hmac_config_get(&policy,&mode));
    assert(fj_hmac_config_init() && fj_hmac_config_get(&policy,&mode));
    fj_hmac_policy_t runtime;
    assert(fj_hmac_policy_init(&runtime,policy,false,0));
    assert(fj_hmac_policy_decide(&runtime,false,false)==FJ_HMAC_DENY);
    assert(!fj_hmac_runtime_init(wrong,false,0));
    assert(!fj_hmac_runtime_enabled());
    assert(fj_hmac_runtime_init(otp,false,0));
    assert(fj_hmac_runtime_enabled());
    assert(fj_hmac_policy_decide(fj_hmac_runtime_policy(),false,false)==FJ_HMAC_DENY);
    fj_hmac_runtime_poll(false,31);
    fj_hmac_runtime_poll(true,32); fj_hmac_runtime_poll(true,63);
    fj_hmac_runtime_poll(false,64); fj_hmac_runtime_poll(false,95);
    assert(fj_hmac_policy_decide(fj_hmac_runtime_policy(),false,false)==FJ_HMAC_ALLOW);
    /* A host disconnect does not reinitialize this device-owned state. */
    fj_hmac_runtime_poll(false,1000);
    assert(fj_hmac_policy_decide(fj_hmac_runtime_policy(),false,false)==FJ_HMAC_ALLOW);
    assert(fj_hmac_runtime_init(otp,false,0)); /* actual device reboot */
    assert(fj_hmac_policy_decide(fj_hmac_runtime_policy(),false,false)==FJ_HMAC_DENY);
    assert(!fj_hmac_runtime_set_policy(FJ_HMAC_AUTO,true,false,0));
    test_state=FJ_STATE_UNLOCKED;
    assert(!fj_hmac_runtime_set_policy(FJ_HMAC_AUTO,true,false,0));
    pin_configured=true;
    assert(!fj_hmac_runtime_set_policy(FJ_HMAC_AUTO,false,false,0));
    assert(fj_hmac_runtime_set_policy(FJ_HMAC_AUTO,true,false,0));
    assert(fj_hmac_policy_decide(fj_hmac_runtime_policy(),false,false)==FJ_HMAC_ALLOW);
    assert(fj_hmac_runtime_set_policy(FJ_HMAC_ARMED,true,false,0));
    assert(fj_hmac_policy_decide(fj_hmac_runtime_policy(),false,false)==FJ_HMAC_DENY);
    /* A torn update must not fall back to an older policy. */
    torn_program=true;
    assert(!fj_hmac_runtime_set_policy(FJ_HMAC_PIN,true,false,0));
    torn_program=false;
    assert(!fj_hmac_runtime_enabled());
    assert(!fj_hmac_config_get(&policy,&mode));
    assert(!fj_hmac_config_init());
    assert(!fj_hmac_config_get(&policy,&mode));
    assert(test_flash[FJ_HMAC_CONFIG_OFFSET-1]==0x71 && test_flash[FJ_KEYS_STAGE_OFFSET]==0x72);
    puts("hmac policy persistence, root mode and interrupted update: ok");
}
