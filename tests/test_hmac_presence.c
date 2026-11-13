#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include "hmac_presence.h"

static void confirm(fj_hmac_presence_t *p, uint32_t t) {
    fj_hmac_presence_poll(p, false, t + 30);
    fj_hmac_presence_poll(p, true, t + 31);
    fj_hmac_presence_poll(p, true, t + 61);
    fj_hmac_presence_poll(p, false, t + 62);
    fj_hmac_presence_poll(p, false, t + 92);
}

int main(void) {
    fj_hmac_presence_t p;
    assert(!fj_hmac_presence_begin(&p, false, 0, 0));
    assert(!fj_hmac_presence_begin(&p, false, 0, UINT32_MAX));
    assert(fj_hmac_presence_begin(&p, true, 0, 1000));
    fj_hmac_presence_poll(&p, true, 50); /* initially held is not a press */
    fj_hmac_presence_poll(&p, false, 51);
    fj_hmac_presence_poll(&p, false, 81);
    fj_hmac_presence_poll(&p, true, 82);
    fj_hmac_presence_poll(&p, false, 90); /* bounce */
    fj_hmac_presence_poll(&p, false, 120);
    assert(!fj_hmac_presence_take(&p, 121));
    assert(fj_hmac_presence_begin(&p, false, 0, 1000));
    confirm(&p, 0);
    assert(fj_hmac_presence_take(&p, 92));
    assert(!fj_hmac_presence_take(&p, 92));
    assert(fj_hmac_presence_begin(&p, false, 0, 100));
    confirm(&p, 0);
    assert(!fj_hmac_presence_take(&p, 100));
    assert(fj_hmac_presence_begin(&p, false, 0, 1000));
    confirm(&p, 0);
    fj_hmac_presence_cancel(&p);
    assert(!fj_hmac_presence_take(&p, 93));
    assert(fj_hmac_presence_begin(&p, false, UINT32_MAX - 40, 1000));
    confirm(&p, UINT32_MAX - 40);
    assert(fj_hmac_presence_take(&p, 52));
    assert(fj_hmac_presence_begin(&p, false, 0, 50));
    fj_hmac_presence_poll(&p, false, 50);
    assert(!fj_hmac_presence_take(&p, 51));
    puts("hmac-secret request presence tests: ok");
}
