#ifndef FJ_HMAC_STORE_H
#define FJ_HMAC_STORE_H
#include <stdbool.h>
#include <stddef.h>
#include "hmac_credential.h"
#include "hmac_root.h"
#include "restore_journal.h"

/* Isolated storage for sealed hmac-secret credentials. This is not an access
 * control API: callers must authorize, protect the wrapping root, and arrange
 * backup/restore and factory wipe before exposing it to CTAP. */
#define FJ_HMAC_STORE_CAPACITY 8u
typedef struct {
    uint8_t credential_id[16];
    uint8_t rp_id_hash[32];
} fj_hmac_credential_info_t;
typedef struct {
    uint8_t used;
    fj_hmac_credential_t credential;
} fj_hmac_backup_entry_t;
typedef struct {
    uint8_t root[32];
    fj_hmac_backup_entry_t entries[FJ_HMAC_STORE_CAPACITY];
} fj_hmac_snapshot_t;
bool fj_hmac_store_init(void);
/* Legacy single-store backup/restore is safe only when this store is ready
 * and contains no root. An unavailable store must fail closed. */
bool fj_hmac_store_legacy_backup_safe(void);
bool fj_hmac_restore_generation(uint32_t *generation);
/* Forget cached root, credential records and flash work buffers. */
void fj_hmac_store_forget_ram(void);
/* Provision only an empty store. The caller must authorize this operation,
 * generate the root, and arrange recovery. Changing an existing root or
 * enabling OTP migration is not implemented. */
bool fj_hmac_store_provision_root(const fj_hmac_root_record_t *record,
                                  const uint8_t otp[32]);
bool fj_hmac_store_open_root(fj_hmac_root_mode_t expected_mode,
                             const uint8_t otp[32], uint8_t root[32]);
bool fj_hmac_store_get(const uint8_t id[16], fj_hmac_credential_t *out);
/* Public metadata only; caller must authorize listing. */
bool fj_hmac_store_list(fj_hmac_credential_info_t *out,size_t capacity,size_t *count);
/* Callback for ordinary CTAP exclusion/collision checks; unavailable store
 * returns true so a storage failure cannot admit a colliding registration. */
bool fj_hmac_store_id_exists(void *ctx,const uint8_t id[16]);
bool fj_hmac_store_put(const fj_hmac_credential_t *credential);
/* The older A/B slot is erased before success. If erasure is interrupted,
 * initialization finishes it before making credentials available. */
bool fj_hmac_store_remove(const uint8_t id[16]);
/* Commit an empty tombstone, then erase the other flash copy. A subsequent
 * init completes an interrupted erase; on failure the store is unavailable. */
bool fj_hmac_store_wipe(void);
/* Sensitive plaintext snapshots must be protected by caller authorization and
 * wiped after use. Restore only into an empty store, in one A/B commit. */
bool fj_hmac_store_export(fj_hmac_root_mode_t expected_mode,
                          const uint8_t otp[32], fj_hmac_snapshot_t *out);
bool fj_hmac_store_restore_empty(const fj_hmac_snapshot_t *snapshot,
                                 const fj_hmac_root_record_t *new_root,
                                 const uint8_t otp[32]);

/* Internal restore staging prototype. The caller must authenticate the backup,
 * block normal service, and preserve the snapshot until stage succeeds. The
 * digest is calculated before beginning the journal transaction. Staging does
 * not change either active slot. This is not yet connected to boot or restore.
 * Development-mode root records contain the root in plaintext, as elsewhere. */
bool fj_hmac_stage_digest(const fj_hmac_snapshot_t *snapshot,
                          const fj_hmac_root_record_t *root,
                          const uint8_t otp[32], const fj_restore_plan_t *plan,
                          uint8_t digest[32]);
bool fj_hmac_stage_write(const fj_hmac_snapshot_t *snapshot,
                         const fj_hmac_root_record_t *root,
                         const uint8_t otp[32], const fj_restore_plan_t *plan);
bool fj_hmac_stage_verify(const fj_restore_plan_t *plan);
/* Requires the matching COMMITTED journal; service remains blocked until the
 * other store is also active and the transaction is finalized. */
bool fj_hmac_stage_activate(const fj_restore_plan_t *plan);
bool fj_hmac_restore_old_active(const fj_restore_plan_t *plan);
bool fj_hmac_stage_is_active(const fj_restore_plan_t *plan);
bool fj_hmac_restore_new_active(const fj_restore_plan_t *plan);
bool fj_hmac_restore_discard_previous(const fj_restore_plan_t *plan);
/* Call only under an authenticated recovery decision. Interrupted erase is
 * repeatable; it must never be used to discard a committed transaction. */
bool fj_hmac_stage_discard(void);
#endif
