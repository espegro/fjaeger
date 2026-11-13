#ifndef FJ_HMAC_CONFIG_H
#define FJ_HMAC_CONFIG_H
#include <stdbool.h>
#include <stdint.h>
#include "hmac_policy.h"
#include "hmac_root.h"

/* Device-local A/B configuration. This does not authorize changes, provision
 * OTP, or authenticate flash against an attacker. The caller must require an
 * unlocked device and a deliberate physical confirmation before enabling a
 * less restrictive mode. Runtime `armed` is never stored here. */
bool fj_hmac_config_init(void);
void fj_hmac_config_forget_ram(void);
/* False means absent/unavailable; caller must not assume an automatic mode. */
bool fj_hmac_config_get(fj_hmac_mode_t *policy,fj_hmac_root_mode_t *root_mode);
/* The existing root must open in the explicitly requested mode. Switching an
 * already configured root mode requires a separate migration, not this API. */
bool fj_hmac_config_set(fj_hmac_mode_t policy,fj_hmac_root_mode_t root_mode,
                        const uint8_t otp[32]);
#endif
