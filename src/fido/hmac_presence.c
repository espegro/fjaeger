#include "hmac_presence.h"
#include <stddef.h>
#include <string.h>

#define DEBOUNCE_MS 30u

void fj_hmac_presence_cancel(fj_hmac_presence_t *p) {
    if (p) memset(p, 0, sizeof(*p));
}

bool fj_hmac_presence_begin(fj_hmac_presence_t *p, bool button_pressed,
                            uint32_t now_ms, uint32_t timeout_ms) {
    if (!p) return false;
    fj_hmac_presence_cancel(p);
    /* Bound durations to make unsigned elapsed-time arithmetic unambiguous. */
    if (!timeout_ms || timeout_ms > UINT32_MAX / 2u) return false;
    p->active = true;
    p->sample = button_pressed;
    p->started_ms = p->changed_ms = now_ms;
    p->timeout_ms = timeout_ms;
    return true;
}

void fj_hmac_presence_poll(fj_hmac_presence_t *p, bool button_pressed,
                           uint32_t now_ms) {
    if (!p || !p->active) return;
    if (now_ms - p->started_ms >= p->timeout_ms) {
        fj_hmac_presence_cancel(p);
        return;
    }
    if (p->confirmed) return;
    if (button_pressed != p->sample) {
        p->sample = button_pressed;
        p->changed_ms = now_ms;
    }
    if (now_ms - p->changed_ms < DEBOUNCE_MS) return;
    if (!p->sample) {
        if (p->released && p->pressed) p->confirmed = true;
        else p->released = true;
    } else if (p->released) {
        p->pressed = true;
    }
}

bool fj_hmac_presence_ready(const fj_hmac_presence_t *p, uint32_t now_ms) {
    return p && p->active && p->confirmed &&
           now_ms - p->started_ms < p->timeout_ms;
}

bool fj_hmac_presence_take(fj_hmac_presence_t *p, uint32_t now_ms) {
    bool result = fj_hmac_presence_ready(p, now_ms);
    fj_hmac_presence_cancel(p);
    return result;
}
