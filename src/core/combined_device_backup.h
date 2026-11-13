#ifndef FJ_COMBINED_DEVICE_BACKUP_H
#define FJ_COMBINED_DEVICE_BACKUP_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "keys.h"

/* Single-threaded firmware caller supplies an already-derived password key,
 * fresh salt/nonce and a stable, authorized keys snapshot. */
bool fj_combined_device_backup(const fj_backup_payload_t *keys,
                               const uint8_t key[32], const uint8_t salt[16],
                               const uint8_t nonce[12], uint8_t *out, size_t cap);
#endif
