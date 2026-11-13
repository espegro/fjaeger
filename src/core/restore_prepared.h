#ifndef FJ_RESTORE_PREPARED_H
#define FJ_RESTORE_PREPARED_H
#include <stdbool.h>
#include <stdint.h>
#include "hmac_store.h"

/* Internal synchronous operation, not a user-facing RESTORE. Before calling,
 * authenticate the complete backup, validate the target policy, block ALL
 * normal services and open a dirty key-store transaction with the complete
 * restored credentials AND freshly wrapped master/verifiers. The supplied
 * hmac snapshot/root must have been explicitly prepared for the chosen
 * protection mode. transaction_id must be fresh random nonzero bytes.
 * The caller must scrub snapshots, roots, OTP and transaction workspaces.
 * Returns false on any failure; normal service must remain blocked and boot
 * recovery must run before using either store. The function always aborts the
 * in-memory keys transaction. This does not cancel concurrent USB requests. */
bool fj_restore_prepared(const fj_hmac_snapshot_t *snapshot,
                         const fj_hmac_root_record_t *root,
                         const uint8_t otp[32],const uint8_t transaction_id[16]);
#endif
