#ifndef FJ_HMAC_SECRET_H
#define FJ_HMAC_SECRET_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* CTAP PIN/UV protocol 1 hmac-secret processing. This primitive does not
 * authorize a request, establish key agreement, or protect credential keys. */
bool fj_hmac_secret_v1(const uint8_t shared[32], const uint8_t cred_random[32],
                       const uint8_t *salt_enc, size_t salt_len,
                       const uint8_t salt_auth[16], uint8_t *out,
                       size_t out_cap);
#endif
