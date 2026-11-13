#ifndef FJ_HMAC_REQUEST_H
#define FJ_HMAC_REQUEST_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "cbor.h"

/* Parsed CTAP2 hmac-secret getAssertion extension input.  This is a parser,
 * not an authorization decision; curve membership must be checked by ECDH. */
typedef struct {
    uint8_t platform_public[65];
    uint8_t salt_enc[64];
    size_t salt_len;
    uint8_t salt_auth[16];
} fj_hmac_request_t;

/* r is positioned immediately after the CBOR map head in item.  Only PIN/UV
 * protocol 1 is accepted.  Invalid input clears the result. */
bool fj_hmac_request_parse(fj_cbor_reader *r, const fj_cbor_item *item,
                           fj_hmac_request_t *out);
#endif
