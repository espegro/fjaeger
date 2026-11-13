#ifndef FJ_FACTORY_CONFIRM_H
#define FJ_FACTORY_CONFIRM_H
#include <stdbool.h>
#include <stdint.h>
#include "hmac_presence.h"

typedef struct {
    fj_hmac_presence_t presence;
    uint32_t session_epoch;
} fj_factory_confirm_t;

typedef enum {
    FJ_FACTORY_CONFIRM_CANCELLED,
    FJ_FACTORY_CONFIRM_WAITING,
    FJ_FACTORY_CONFIRM_APPROVED
} fj_factory_confirm_result_t;

/* Require exactly RESET YES after the FACTORY command. */
bool fj_factory_confirm_command(const char *action,const char *confirmation,const char *extra);
/* Caller must first validate the exact command and explicit YES. */
bool fj_factory_confirm_begin(fj_factory_confirm_t *c,bool unlocked,bool connected,
                              bool fido_pending,uint32_t epoch,bool pressed,uint32_t now);
fj_factory_confirm_result_t fj_factory_confirm_poll(fj_factory_confirm_t *c,
        bool unlocked,bool connected,bool fido_pending,uint32_t epoch,bool pressed,uint32_t now);
void fj_factory_confirm_cancel(fj_factory_confirm_t *c);
#endif
