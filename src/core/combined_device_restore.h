#ifndef FJ_COMBINED_DEVICE_RESTORE_H
#define FJ_COMBINED_DEVICE_RESTORE_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "restore_bundle.h"

/* One authenticated restore may be prepared at a time. The caller keeps the
 * keys output stable, cancels on lock/disconnect, and excludes all services
 * during commit. An unsuccessful commit requires journal recovery. */
bool fj_combined_device_restore_prepare(const uint8_t *blob,size_t len,
                                         const uint8_t key[32],fj_backup_payload_t *keys);
bool fj_combined_device_restore_commit(const fj_backup_payload_t *keys,
                                       const fj_restore_wraps_t *wraps,
                                       const uint8_t salt[16],const uint8_t nonce[12],
                                       const uint8_t transaction_id[16]);
void fj_combined_device_restore_cancel(void);
#endif
