#ifndef FJ_RESTORE_BUNDLE_H
#define FJ_RESTORE_BUNDLE_H
#include <stdbool.h>
#include <stdint.h>
#include "combined_backup.h"

/* Independently salted KDF results prepared cooperatively from the new
 * passphrase and PUK. wrap_key fields are XOR masks for the recovered master,
 * matching existing key-store format. Caller must securely erase this struct. */
typedef struct {
    uint8_t pass_hash[32], pass_salt[16];
    uint8_t pass_wrap_key[32], pass_wrap_salt[16];
    uint8_t puk_hash[32], puk_salt[16];
    uint8_t puk_wrap_key[32], puk_wrap_salt[16];
} fj_restore_wraps_t;

/* Internal synchronous restore from an already authenticated combined backup.
 * The caller must suspend every normal service, explicitly choose target root
 * protection (no fallback), provide fresh random wrapping salt, GCM nonce and
 * transaction ID, then scrub input snapshots, wraps and OTP. On any failure,
 * keep service stopped and perform boot recovery before proceeding. The
 * operation does not synchronize or invalidate USB/FIDO caches. The target
 * must already have a valid, accessible root and configuration in the same
 * mode; otherwise a committed restore could disagree with boot policy. */
bool fj_restore_bundle(const fj_backup_payload_t *keys,
                       const fj_hmac_snapshot_t *hmac,
                       const fj_restore_wraps_t *wraps,
                       fj_hmac_root_mode_t mode, const uint8_t otp[32],
                       const uint8_t root_salt[16], const uint8_t root_nonce[12],
                       const uint8_t transaction_id[16]);
#endif
