#ifndef FJ_HMAC_ROOT_H
#define FJ_HMAC_ROOT_H
#include <stdbool.h>
#include <stdint.h>

/* Development root records are deliberately not secret at rest. OTP mode
 * wraps the SAME random root so explicitly migrating preserves credentials.
 * This is an isolated codec, not an OTP reader, provisioning or policy API. */
typedef enum {
    FJ_HMAC_ROOT_DEVELOPMENT = 1,
    FJ_HMAC_ROOT_OTP = 2
} fj_hmac_root_mode_t;

typedef struct {
    uint8_t version;
    uint8_t mode;
    uint8_t salt[16];
    uint8_t nonce[12];
    uint8_t wrapped_root[32];
    uint8_t tag[16];
} fj_hmac_root_record_t;

/* Caller supplies a cryptographically random root, salt and unique nonce;
 * OTP mode additionally requires the provisioned 32-byte device secret.
 * Output is unchanged on failure. No OTP bits are programmed by these APIs. */
bool fj_hmac_root_create(fj_hmac_root_record_t *record,
                         fj_hmac_root_mode_t mode, const uint8_t root[32],
                         const uint8_t otp[32], const uint8_t salt[16],
                         const uint8_t nonce[12]);
/* expected_mode must be supplied by the storage policy; never infer fallback
 * from an OTP read failure. Failure clears root. Authenticating that policy
 * against an attacker who can rewrite flash requires a hardware root of trust. */
bool fj_hmac_root_open(const fj_hmac_root_record_t *record,
                       fj_hmac_root_mode_t expected_mode,
                       const uint8_t otp[32], uint8_t root[32]);
#endif
