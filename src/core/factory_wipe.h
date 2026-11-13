#ifndef FJ_FACTORY_WIPE_H
#define FJ_FACTORY_WIPE_H
#include <stdbool.h>
/* Internal flash wipe. Caller must stop services and clear live secrets. The
 * journal must be initialized and CLEAN before start. A failed call requires
 * recovery before any service; it must never be reported as a successful wipe.
 * The MSC ciphertext is not erased; erasing its wrapping key makes it unusable.
 * OTP, external backups, and arbitrary non-store flash are not erased. */
bool fj_factory_wipe_start(void);
/* Resume a persisted WIPING decision, including after restart. */
bool fj_factory_wipe_recover(void);
/* Stop normal service after an unrecoverable runtime wipe failure. */
_Noreturn void fj_factory_wipe_halt(void);
#endif
