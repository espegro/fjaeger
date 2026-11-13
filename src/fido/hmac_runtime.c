#include "hmac_runtime.h"
#include "hmac_config.h"
#include "hmac_store.h"
#include "crypto.h"
#include "keys.h"
#include "state.h"
#include <stddef.h>

static fj_hmac_policy_t runtime_policy;
static fj_hmac_root_mode_t runtime_root_mode;
static const uint8_t *runtime_otp;
static bool enabled;

void fj_hmac_runtime_forget(void) {
    fj_secure_zero(&runtime_policy,sizeof(runtime_policy));
    runtime_root_mode=0; runtime_otp=NULL; enabled=false;
}
bool fj_hmac_runtime_init(const uint8_t otp[32],bool pressed,uint32_t now) {
    fj_hmac_runtime_forget();
    if (!fj_hmac_store_init() || !fj_hmac_config_init()) return false;
    fj_hmac_mode_t policy; fj_hmac_root_mode_t mode;
    /* An erased configuration means the feature has not been enabled. */
    if (!fj_hmac_config_get(&policy,&mode)) return true;
    uint8_t root[32]={0};
    bool valid=fj_hmac_store_open_root(mode,otp,root);
    fj_secure_zero(root,sizeof(root));
    if (!valid || !fj_hmac_policy_init(&runtime_policy,policy,pressed,now)) return false;
    runtime_root_mode=mode; runtime_otp=otp; enabled=true; return true;
}
bool fj_hmac_runtime_enabled(void) { return enabled; }
const fj_hmac_policy_t *fj_hmac_runtime_policy(void) { return enabled ? &runtime_policy : NULL; }
bool fj_hmac_runtime_root_mode(fj_hmac_root_mode_t *mode) {
    if (!enabled || !mode) return false;
    *mode=runtime_root_mode; return true;
}
bool fj_hmac_runtime_provision_development(bool confirmed,bool pressed,uint32_t now) {
    if (enabled || !confirmed || fj_state_get()!=FJ_STATE_UNLOCKED ||
        !fj_state_ctap2_pin_configured()) return false;
    /* Reload both stores so corruption and a pre-existing configuration are
     * detected before attempting any write. Never infer an OTP fallback. */
    if (!fj_hmac_store_init() || !fj_hmac_config_init()) return false;
    fj_hmac_mode_t existing_policy; fj_hmac_root_mode_t existing_mode;
    if (fj_hmac_config_get(&existing_policy,&existing_mode)) return false;
    uint8_t root[32]={0},salt[16]={0},nonce[12]={0};
    fj_hmac_root_record_t record={0};
    bool ok=fj_hmac_store_open_root(FJ_HMAC_ROOT_DEVELOPMENT,NULL,root);
    if (!ok) {
        fj_random(root,sizeof(root)); fj_random(salt,sizeof(salt)); fj_random(nonce,sizeof(nonce));
        ok=fj_hmac_root_create(&record,FJ_HMAC_ROOT_DEVELOPMENT,root,NULL,salt,nonce) &&
           fj_hmac_store_provision_root(&record,NULL);
    }
    fj_secure_zero(root,sizeof(root)); fj_secure_zero(salt,sizeof(salt));
    fj_secure_zero(nonce,sizeof(nonce)); fj_secure_zero(&record,sizeof(record));
    if (!ok || !fj_hmac_config_set(FJ_HMAC_PIN_BUTTON,FJ_HMAC_ROOT_DEVELOPMENT,NULL)) {
        fj_hmac_runtime_forget(); return false;
    }
    return fj_hmac_runtime_init(NULL,pressed,now);
}
void fj_hmac_runtime_poll(bool pressed,uint32_t now) {
    if (enabled) fj_hmac_policy_poll(&runtime_policy,pressed,now);
}
bool fj_hmac_runtime_set_policy(fj_hmac_mode_t mode,bool confirmed,bool pressed,uint32_t now) {
    if (!enabled || !confirmed || fj_state_get()!=FJ_STATE_UNLOCKED ||
        !fj_state_ctap2_pin_configured() || mode<FJ_HMAC_PIN_BUTTON || mode>FJ_HMAC_ARMED) return false;
    if (!fj_hmac_config_set(mode,runtime_root_mode,runtime_otp)) {
        /* A failed persistent update must never continue with stale policy. */
        fj_hmac_runtime_forget(); return false;
    }
    if (!fj_hmac_policy_init(&runtime_policy,mode,pressed,now)) {
        fj_hmac_runtime_forget(); return false;
    }
    return true;
}
