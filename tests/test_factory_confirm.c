#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include "factory_confirm.h"

static fj_factory_confirm_result_t poll(fj_factory_confirm_t *c,bool pressed,uint32_t t) {
    return fj_factory_confirm_poll(c,true,true,false,7,pressed,t);
}
int main(void) {
    fj_factory_confirm_t c={0};
    assert(!fj_factory_confirm_command(NULL,NULL,NULL));
    assert(!fj_factory_confirm_command("reset",NULL,NULL));
    assert(!fj_factory_confirm_command("reset","no",NULL));
    assert(!fj_factory_confirm_command("reset","yes","extra"));
    assert(!fj_factory_confirm_command("reboot","yes",NULL));
    assert(fj_factory_confirm_command("RESET","YES",NULL));
    assert(fj_factory_confirm_command("reset","yes",NULL));
    assert(!fj_factory_confirm_begin(&c,false,true,false,7,false,0));
    assert(!fj_factory_confirm_begin(&c,true,false,false,7,false,0));
    assert(!fj_factory_confirm_begin(&c,true,true,true,7,false,0));
    assert(fj_factory_confirm_begin(&c,true,true,false,7,true,0));
    assert(!fj_factory_confirm_begin(&c,true,true,false,7,false,0));
    assert(poll(&c,true,100)==FJ_FACTORY_CONFIRM_WAITING); /* held at start */
    assert(poll(&c,false,101)==FJ_FACTORY_CONFIRM_WAITING);
    assert(poll(&c,false,131)==FJ_FACTORY_CONFIRM_WAITING);
    assert(poll(&c,true,132)==FJ_FACTORY_CONFIRM_WAITING);
    assert(poll(&c,false,140)==FJ_FACTORY_CONFIRM_WAITING); /* bounce */
    assert(poll(&c,false,170)==FJ_FACTORY_CONFIRM_WAITING);
    assert(poll(&c,true,171)==FJ_FACTORY_CONFIRM_WAITING);
    assert(poll(&c,true,201)==FJ_FACTORY_CONFIRM_WAITING);
    assert(poll(&c,false,202)==FJ_FACTORY_CONFIRM_WAITING);
    assert(poll(&c,false,232)==FJ_FACTORY_CONFIRM_APPROVED);
    assert(poll(&c,false,233)==FJ_FACTORY_CONFIRM_CANCELLED);
    for (unsigned why=0;why<4;why++) {
        assert(fj_factory_confirm_begin(&c,true,true,false,7,false,0));
        assert(fj_factory_confirm_poll(&c,why!=0,why!=1,why==2,why==3?8:7,false,31)==FJ_FACTORY_CONFIRM_CANCELLED);
        assert(poll(&c,false,32)==FJ_FACTORY_CONFIRM_CANCELLED);
    }
    assert(fj_factory_confirm_begin(&c,true,true,false,7,false,0));
    assert(poll(&c,false,30000)==FJ_FACTORY_CONFIRM_CANCELLED);
    assert(fj_factory_confirm_begin(&c,true,true,false,7,false,UINT32_MAX-20));
    assert(poll(&c,false,10)==FJ_FACTORY_CONFIRM_WAITING);
    assert(poll(&c,true,11)==FJ_FACTORY_CONFIRM_WAITING);
    assert(poll(&c,true,41)==FJ_FACTORY_CONFIRM_WAITING);
    assert(poll(&c,false,42)==FJ_FACTORY_CONFIRM_WAITING);
    assert(poll(&c,false,72)==FJ_FACTORY_CONFIRM_APPROVED);
    puts("factory reset confirmation: ok");
}
