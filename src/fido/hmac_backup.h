#ifndef FJ_HMAC_BACKUP_H
#define FJ_HMAC_BACKUP_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "hmac_store.h"

/* Prototype encrypted backup codec; the caller must derive an independent key
 * with a salt and password KDF, supply a fresh nonce and scrub snapshots. */
#define FJ_HMAC_BACKUP_HEADER 20u
#define FJ_HMAC_BACKUP_ENTRY (1u + 16u + 32u + 65u + 12u + 96u + 16u)
#define FJ_HMAC_BACKUP_PAYLOAD (32u + FJ_HMAC_STORE_CAPACITY * FJ_HMAC_BACKUP_ENTRY)
#define FJ_HMAC_BACKUP_SIZE (FJ_HMAC_BACKUP_HEADER + FJ_HMAC_BACKUP_PAYLOAD + 16u)

bool fj_hmac_snapshot_valid(const fj_hmac_snapshot_t *snapshot);
bool fj_hmac_backup_seal(const fj_hmac_snapshot_t *snapshot,
                         const uint8_t key[32], const uint8_t nonce[12],
                         uint8_t *out, size_t capacity);
bool fj_hmac_backup_open(const uint8_t *blob, size_t len,
                         const uint8_t key[32], fj_hmac_snapshot_t *out);
#endif
