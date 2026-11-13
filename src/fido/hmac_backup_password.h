#ifndef FJ_HMAC_BACKUP_PASSWORD_H
#define FJ_HMAC_BACKUP_PASSWORD_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "hmac_backup.h"

/* Standalone development prototype; KDF is synchronous. Do not call in the USB
 * task or expose until converted to a cooperative job and integrated with a
 * crash-safe, authorized, versioned backup/restore lifecycle. */
#define FJ_HMAC_PASSWORD_HEADER 24u /* magic(4), version(1), reserved(3), salt(16) */
#define FJ_HMAC_PASSWORD_BACKUP_SIZE (FJ_HMAC_PASSWORD_HEADER + FJ_HMAC_BACKUP_SIZE)

/* Caller supplies fresh random salt and nonce. Inputs are not retained. */
bool fj_hmac_password_backup_seal(const fj_hmac_snapshot_t *snapshot,
                                  const uint8_t *password, size_t password_len,
                                  const uint8_t salt[16], const uint8_t nonce[12],
                                  uint8_t *out, size_t capacity);
bool fj_hmac_password_backup_open(const uint8_t *blob, size_t len,
                                  const uint8_t *password, size_t password_len,
                                  fj_hmac_snapshot_t *out);
#endif
