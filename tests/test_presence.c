#include <assert.h>
#include <stdio.h>
#include <string.h>
#include "u2f.h"
#include "state.h"
#include "keys.h"
#include "ctap2.h"
#include "hmac_ctap.h"
#include "hmac_runtime.h"

uint32_t test_now;
static bool button, mode = true, mounted = true, waiting;
static fj_state_t state = FJ_STATE_UNLOCKED;
static unsigned dispatched, profile;
static bool hmac_enabled, hmac_present;
static unsigned hmac_dispatched;
static uint32_t session_epoch;
static fj_hmac_policy_t hmac_policy={.mode=FJ_HMAC_PIN_BUTTON};
uint32_t fj_state_session_epoch(void) { return session_epoch; }
bool fj_hmac_runtime_enabled(void) { return hmac_enabled; }
const fj_hmac_policy_t *fj_hmac_runtime_policy(void) { return hmac_enabled ? &hmac_policy : NULL; }
bool fj_hmac_runtime_root_mode(fj_hmac_root_mode_t *m) { if (!hmac_enabled) return false; *m=FJ_HMAC_ROOT_DEVELOPMENT; return true; }
bool fj_ctap2_normal_id_exists(void *ctx,const uint8_t id[16]) { (void)ctx; (void)id; return false; }
fj_hmac_route_t fj_hmac_ctap_classify(const uint8_t *m,size_t n) {
    return n>1 && m[1]==0xaa ? FJ_HMAC_ROUTE_HMAC : FJ_HMAC_ROUTE_NORMAL;
}
bool fj_hmac_ctap_preflight(const uint8_t *m,size_t n,const fj_hmac_ctap_context_t *c,uint8_t *o,size_t cap,size_t *w) {
    (void)m;(void)n;(void)c;(void)o;(void)cap;(void)w;return false;
}
size_t fj_hmac_ctap_dispatch(const uint8_t *m,size_t n,const fj_hmac_ctap_context_t *c,uint8_t *o,size_t cap) {
    (void)m; (void)n; assert(cap && c->normal_id_exists); hmac_dispatched++; hmac_present=c->user_present; o[0]=0; return 1;
}
bool fj_boot_button_pressed(void) { return button; }
bool fj_keys_presence_button(void) { return mode; }
unsigned fj_keys_active_profile(void) { return profile; }
fj_state_t fj_state_get(void) { return state; }
void fj_led_set_presence_waiting(bool b) { waiting = b; }
bool tud_mounted(void) { return mounted; }
bool tud_hid_ready(void) { return false; }
bool tud_hid_n_report(uint8_t i, uint8_t id, const void *d, uint16_t n) { (void)i; (void)id; (void)d; (void)n; return true; }
void fj_random(void *p, size_t n) { memset(p, 1, n); }
size_t fj_ctap2_dispatch(const uint8_t *msg, size_t len, uint8_t *out, size_t cap) {
    (void)msg; (void)len; assert(cap); dispatched++; out[0] = 0; return 1;
}
static void frame(uint32_t cid, uint8_t cmd, const uint8_t *payload, unsigned len) {
    uint8_t f[64] = {0};
    f[0]=cid>>24; f[1]=cid>>16; f[2]=cid>>8; f[3]=cid;
    f[4]=cmd | 0x80; f[5]=len>>8; f[6]=len;
    if (len) memcpy(f+7,payload,len);
    fj_u2f_hid_rx(f,sizeof(f));
}
static void tick(unsigned ms) { test_now += ms; fj_u2f_task(); }
static void drain(void) { uint8_t b[64]; while (fj_u2f_pop_report(b)) {} }
static int reply(uint8_t cmd, uint8_t value) {
    uint8_t b[64];
    while (fj_u2f_pop_report(b)) if (b[4] == (uint8_t)(cmd|0x80) && b[7] == value) return 1;
    return 0;
}
int main(void) {
    uint8_t get[] = {2};
    fj_u2f_init();
    /* Held before request cannot authorize it; release and a fresh press can. */
    button = true; frame(1,0x10,get,1); assert(waiting && !dispatched);
    tick(100); assert(!dispatched); button=false; tick(1); tick(31);
    button=true; tick(1); tick(31); assert(dispatched==0 && waiting);
    button=false; tick(1); tick(31); assert(dispatched==1 && !waiting);
    assert(reply(0x10,0));
    /* Cancellation cancels the pending request and returns CTAP error. */
    button=false; frame(1,0x10,get,1); tick(31); frame(1,0x11,NULL,0);
    assert(!waiting && dispatched==1 && reply(0x10,0x2d));
    frame(1,0x10,get,1); tick(30001); assert(!waiting && dispatched==1 && reply(0x10,0x2f));
    frame(1,0x10,get,1); state=FJ_STATE_LOCKED; tick(1); assert(!waiting && dispatched==1); drain();
    state=FJ_STATE_UNLOCKED; frame(1,0x10,get,1); profile++; tick(1); assert(!waiting && dispatched==1); drain();
    frame(1,0x10,get,1); tick(31); button=true; tick(1); tick(31);
    mounted=false; tick(1); assert(!waiting && dispatched==1); drain();
    mounted=true; button=false; frame(1,0x10,get,1); tick(31);
    button=true; tick(1); tick(31); button=false; tick(1); tick(31);
    assert(dispatched==2 && !waiting && reply(0x10,0));
    mode=false; frame(1,0x10,get,1); assert(dispatched==3 && !waiting && reply(0x10,0));
    uint8_t hmget[]={2,0xaa},hmmake[]={1,0xaa};
    hmac_enabled=true; state=FJ_STATE_LOCKED; button=false;
    frame(1,0x10,hmget,2); assert(waiting && hmac_dispatched==0);
    tick(31); button=true; tick(1); tick(31); button=false; tick(1); tick(31);
    assert(!waiting && hmac_dispatched==1 && hmac_present && reply(0x10,0));
    frame(1,0x10,hmmake,2); assert(!waiting && hmac_dispatched==1 && reply(0x10,0x27));
    hmac_policy.mode=FJ_HMAC_AUTO;
    frame(1,0x10,hmget,2); assert(!waiting && hmac_dispatched==2 && !hmac_present && reply(0x10,0));
    hmac_policy.mode=FJ_HMAC_PIN_BUTTON;
    frame(1,0x10,hmget,2); assert(waiting); session_epoch++; tick(1);
    assert(!waiting && hmac_dispatched==2); drain();
    hmac_policy.mode=FJ_HMAC_PIN;
    frame(1,0x10,hmget,2); assert(!waiting && hmac_dispatched==3 && !hmac_present && reply(0x10,0));
    puts("presence transport tests: ok");
}
