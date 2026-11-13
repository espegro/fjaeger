#ifndef FJ_HMAC_RUNTIME_H
#define FJ_HMAC_RUNTIME_H
#include <stdbool.h>
#include <stdint.h>
#include "hmac_policy.h"
#include "hmac_root.h"

/* Internal feature runtime; not connected to CTAP, console or a physical OTP
 * provider. The caller initializes on device boot, never on a
 * USB reconnect. OTP pointer, when supplied, must remain stable and secret. */
bool fj_hmac_runtime_init(const uint8_t otp[32],bool button_pressed,uint32_t now_ms);
bool fj_hmac_runtime_enabled(void);
const fj_hmac_policy_t *fj_hmac_runtime_policy(void);
bool fj_hmac_runtime_root_mode(fj_hmac_root_mode_t *mode);
/* Explicit, development-only initialization. Requires a fresh physical
 * confirmation and a configured PIN on an unlocked device. An interrupted
 * operation may be retried without replacing an existing development root.
 * This does not provide backup or expose the feature to CTAP. */
bool fj_hmac_runtime_provision_development(bool confirmed, bool button_pressed,
                                           uint32_t now_ms);
void fj_hmac_runtime_poll(bool button_pressed,uint32_t now_ms);
/* Requires a currently unlocked device, a configured FIDO PIN and a fresh
 * physical confirmation supplied by the caller. Mode changes disarm ARMED. */
bool fj_hmac_runtime_set_policy(fj_hmac_mode_t mode,bool confirmed,
                                bool button_pressed,uint32_t now_ms);
/* Clear volatile state on reset/factory wipe; not on host USB disconnect. */
void fj_hmac_runtime_forget(void);
#endif
