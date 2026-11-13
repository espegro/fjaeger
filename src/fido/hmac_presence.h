#ifndef FJ_HMAC_PRESENCE_H
#define FJ_HMAC_PRESENCE_H
#include <stdbool.h>
#include <stdint.h>

/* One instance belongs to one pending request. The owner must cancel it on
 * disconnect, cancellation, lock/profile changes or token invalidation. */
typedef struct {
    uint32_t started_ms, changed_ms, timeout_ms;
    bool active, sample, released, pressed, confirmed;
} fj_hmac_presence_t;

bool fj_hmac_presence_begin(fj_hmac_presence_t *p, bool button_pressed,
                            uint32_t now_ms, uint32_t timeout_ms);
void fj_hmac_presence_poll(fj_hmac_presence_t *p, bool button_pressed,
                           uint32_t now_ms);
bool fj_hmac_presence_ready(const fj_hmac_presence_t *p, uint32_t now_ms);
/* Confirmation is valid once and expires at the original deadline. */
bool fj_hmac_presence_take(fj_hmac_presence_t *p, uint32_t now_ms);
void fj_hmac_presence_cancel(fj_hmac_presence_t *p);
#endif
