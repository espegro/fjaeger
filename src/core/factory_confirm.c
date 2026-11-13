#include "factory_confirm.h"
#include <stddef.h>
#include <strings.h>

#define CONFIRM_TIMEOUT_MS 30000u

bool fj_factory_confirm_command(const char *action,const char *confirmation,const char *extra) {
    return action && confirmation && !extra &&
           strcasecmp(action,"reset")==0 && strcasecmp(confirmation,"yes")==0;
}

void fj_factory_confirm_cancel(fj_factory_confirm_t *c) {
    if (!c) return;
    fj_hmac_presence_cancel(&c->presence);
    c->session_epoch=0;
}
bool fj_factory_confirm_begin(fj_factory_confirm_t *c,bool unlocked,bool connected,
                              bool fido_pending,uint32_t epoch,bool pressed,uint32_t now) {
    if (!c || c->presence.active || !unlocked || !connected || fido_pending) return false;
    c->session_epoch=epoch;
    if (!fj_hmac_presence_begin(&c->presence,pressed,now,CONFIRM_TIMEOUT_MS)) {
        fj_factory_confirm_cancel(c); return false;
    }
    return true;
}
fj_factory_confirm_result_t fj_factory_confirm_poll(fj_factory_confirm_t *c,
        bool unlocked,bool connected,bool fido_pending,uint32_t epoch,bool pressed,uint32_t now) {
    if (!c || !c->presence.active) return FJ_FACTORY_CONFIRM_CANCELLED;
    if (!unlocked || !connected || fido_pending || epoch!=c->session_epoch ||
        now-c->presence.started_ms>=c->presence.timeout_ms) {
        fj_factory_confirm_cancel(c); return FJ_FACTORY_CONFIRM_CANCELLED;
    }
    fj_hmac_presence_poll(&c->presence,pressed,now);
    if (fj_hmac_presence_ready(&c->presence,now)) {
        bool approved=fj_hmac_presence_take(&c->presence,now);
        fj_factory_confirm_cancel(c);
        return approved ? FJ_FACTORY_CONFIRM_APPROVED : FJ_FACTORY_CONFIRM_CANCELLED;
    }
    return FJ_FACTORY_CONFIRM_WAITING;
}
