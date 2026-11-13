#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include "hmac_policy.h"

int main(void) {
    fj_hmac_policy_t p;
    assert(fj_hmac_policy_init(&p, FJ_HMAC_ARMED, false, 0));
    assert(fj_hmac_policy_decide(&p, false, false) == FJ_HMAC_DENY);
    /* Noise and a held button do not arm; release, press, release is needed. */
    fj_hmac_policy_poll(&p, true, 5); fj_hmac_policy_poll(&p, false, 10);
    fj_hmac_policy_poll(&p, false, 41); fj_hmac_policy_poll(&p, true, 42);
    fj_hmac_policy_poll(&p, true, 73);
    assert(fj_hmac_policy_decide(&p, false, false) == FJ_HMAC_DENY);
    fj_hmac_policy_poll(&p, false, 74); fj_hmac_policy_poll(&p, false, 105);
    assert(fj_hmac_policy_decide(&p, false, false) == FJ_HMAC_ALLOW);
    /* Host USB disconnects do not call init and cannot clear the latch. */
    fj_hmac_policy_poll(&p, false, 1000);
    assert(fj_hmac_policy_decide(&p, false, false) == FJ_HMAC_ALLOW);
    /* A device reset or power cycle calls init and clears the latch. */
    assert(fj_hmac_policy_init(&p, FJ_HMAC_ARMED, true, 0));
    fj_hmac_policy_poll(&p, true, 100);
    assert(fj_hmac_policy_decide(&p, true, true) == FJ_HMAC_DENY);
    assert(fj_hmac_policy_init(&p, FJ_HMAC_PIN_BUTTON, false, 0));
    assert(fj_hmac_policy_decide(&p, false, true) == FJ_HMAC_DENY);
    assert(fj_hmac_policy_decide(&p, true, false) == FJ_HMAC_NEEDS_PRESS);
    assert(fj_hmac_policy_decide(&p, true, true) == FJ_HMAC_ALLOW);
    assert(fj_hmac_policy_init(&p, FJ_HMAC_PIN, false, 0));
    assert(fj_hmac_policy_decide(&p, false, false) == FJ_HMAC_DENY);
    assert(fj_hmac_policy_decide(&p, true, false) == FJ_HMAC_ALLOW);
    assert(fj_hmac_policy_init(&p, FJ_HMAC_AUTO, false, 0));
    assert(fj_hmac_policy_decide(&p, false, false) == FJ_HMAC_ALLOW);
    assert(fj_hmac_policy_init(&p, FJ_HMAC_ARMED, false, UINT32_MAX - 10));
    fj_hmac_policy_poll(&p, false, 20); /* monotonic millisecond wrap */
    fj_hmac_policy_poll(&p, true, 21); fj_hmac_policy_poll(&p, true, 52);
    fj_hmac_policy_poll(&p, false, 53); fj_hmac_policy_poll(&p, false, 84);
    assert(fj_hmac_policy_decide(&p, false, false) == FJ_HMAC_ALLOW);
    assert(fj_hmac_policy_init(&p, FJ_HMAC_ARMED, false, 85));
    assert(fj_hmac_policy_decide(&p, false, false) == FJ_HMAC_DENY);
    assert(!fj_hmac_policy_init(&p, (fj_hmac_mode_t)99, false, 0));
    assert(fj_hmac_policy_decide(&p, false, false) == FJ_HMAC_DENY);
    puts("hmac-secret policy state tests: ok");
}
