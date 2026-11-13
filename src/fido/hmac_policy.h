#ifndef FJ_HMAC_POLICY_H
#define FJ_HMAC_POLICY_H
#include <stdbool.h>
#include <stdint.h>

/* Policy for a future independent hmac-secret credential. This module does
 * not authorize CTAP requests by itself: the caller must verify any PIN token
 * against the request and only set presence after a fresh physical press. */
typedef enum {
    FJ_HMAC_PIN_BUTTON,
    FJ_HMAC_PIN,
    FJ_HMAC_AUTO,
    FJ_HMAC_ARMED
} fj_hmac_mode_t;

typedef struct {
    fj_hmac_mode_t mode;
    bool armed;
    bool sampled_button;
    bool released;
    bool pressed;
    uint32_t changed_ms;
} fj_hmac_policy_t;

typedef enum {
    FJ_HMAC_DENY,
    FJ_HMAC_NEEDS_PRESS,
    FJ_HMAC_ALLOW
} fj_hmac_decision_t;

/* Call on every device boot and when changing mode, not on USB reconnect. */
bool fj_hmac_policy_init(fj_hmac_policy_t *policy, fj_hmac_mode_t mode,
                         bool button_pressed, uint32_t now_ms);
/* Poll the actual button. A fresh stable press and release arms ARMED mode. */
void fj_hmac_policy_poll(fj_hmac_policy_t *policy, bool button_pressed,
                         uint32_t now_ms);
/* pin_verified and user_present must refer to this request, not stale tokens. */
fj_hmac_decision_t fj_hmac_policy_decide(const fj_hmac_policy_t *policy,
                                         bool pin_verified, bool user_present);
#endif
