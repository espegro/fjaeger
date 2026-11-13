#ifndef FJ_COMBINED_BACKUP_H
#define FJ_COMBINED_BACKUP_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "keys.h"
#include "hmac_backup.h"

/* Internal authenticated codec, not yet a user-facing backup format. The
 * caller derives an independent key with a salted password KDF, generates a
 * fresh unique nonce, authorizes access, and wipes both plaintext snapshots.
 * Separate, non-overlapping output, workspace, and input buffers are required.
 * Workspace contains plaintext secrets temporarily and is wiped before return.
 * Native key-payload layout is versioned implicitly like the existing v3
 * backup; any layout change requires a new format version or migration. */
#define FJ_COMBINED_BACKUP_HEADER 32u
#define FJ_COMBINED_BACKUP_PAYLOAD (sizeof(fj_backup_payload_t) + FJ_HMAC_BACKUP_SIZE)
#define FJ_COMBINED_BACKUP_SIZE (FJ_COMBINED_BACKUP_HEADER + FJ_COMBINED_BACKUP_PAYLOAD + 16u)

/* Validate the persistent key payload before staging it for restore. */
bool fj_combined_backup_keys_valid(const fj_backup_payload_t *keys);
/* Both credential namespaces must remain disjoint across all profiles. */
bool fj_combined_backup_pair_valid(const fj_backup_payload_t *keys,
                                   const fj_hmac_snapshot_t *hmac);

bool fj_combined_backup_seal(const fj_backup_payload_t *keys,
                             const fj_hmac_snapshot_t *hmac,
                             const uint8_t key[32], const uint8_t nonce[12],
                             uint8_t *out, size_t out_len,
                             uint8_t *workspace, size_t workspace_len);
bool fj_combined_backup_open(const uint8_t *blob, size_t blob_len,
                             const uint8_t key[32],
                             fj_backup_payload_t *keys, fj_hmac_snapshot_t *hmac,
                             uint8_t *workspace, size_t workspace_len);
#endif
