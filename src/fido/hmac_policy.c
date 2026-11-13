#include "hmac_policy.h"
#include <stddef.h>

#define BUTTON_DEBOUNCE_MS 30u

bool fj_hmac_policy_init(fj_hmac_policy_t *p, fj_hmac_mode_t mode,
                         bool button_pressed, uint32_t now_ms) {
    if (!p) return false;
    /* An invalid or corrupt mode must never enable automatic access. */
    p->mode = FJ_HMAC_PIN_BUTTON;
    p->armed = p->released = p->pressed = false;
    p->sampled_button = button_pressed;
    p->changed_ms = now_ms;
    if (mode < FJ_HMAC_PIN_BUTTON || mode > FJ_HMAC_ARMED) return false;
    p->mode = mode;
    return true;
}

void fj_hmac_policy_poll(fj_hmac_policy_t *p, bool button_pressed,
                         uint32_t now_ms) {
    if (!p || p->mode != FJ_HMAC_ARMED || p->armed) return;
    if (button_pressed != p->sampled_button) {
        p->sampled_button = button_pressed;
        p->changed_ms = now_ms;
    }
    if (now_ms - p->changed_ms < BUTTON_DEBOUNCE_MS) return;
    if (!button_pressed) {
        if (p->released && p->pressed) p->armed = true;
        else p->released = true;
    } else if (p->released) {
        p->pressed = true;
    }
}

fj_hmac_decision_t fj_hmac_policy_decide(const fj_hmac_policy_t *p,
                                         bool pin_verified, bool user_present) {
    if (!p) return FJ_HMAC_DENY;
    switch (p->mode) {
    case FJ_HMAC_PIN_BUTTON:
        if (!pin_verified) return FJ_HMAC_DENY;
        return user_present ? FJ_HMAC_ALLOW : FJ_HMAC_NEEDS_PRESS;
    case FJ_HMAC_PIN: return pin_verified ? FJ_HMAC_ALLOW : FJ_HMAC_DENY;
    case FJ_HMAC_AUTO: return FJ_HMAC_ALLOW;
    case FJ_HMAC_ARMED: return p->armed ? FJ_HMAC_ALLOW : FJ_HMAC_DENY;
    default: return FJ_HMAC_DENY;
    }
}
