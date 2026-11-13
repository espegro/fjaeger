#ifndef FJ_HMAC_CREDENTIAL_H
#define FJ_HMAC_CREDENTIAL_H
#include <stdbool.h>
#include <stdint.h>

/* Separate from normal SSH/WebAuthn credentials and the device CWK. A future
 * storage owner must persist, back up, and authorize these records atomically.
 * Possession of the wrapping root is sufficient to decrypt a record. */
#define FJ_HMAC_MATERIAL_LEN 96u /* signing scalar || random UV || random no-UV */
typedef struct {
    uint8_t credential_id[16];
    uint8_t rp_id_hash[32];
    uint8_t public_key[65];
    uint8_t nonce[12];
    uint8_t ciphertext[FJ_HMAC_MATERIAL_LEN];
    uint8_t tag[16];
} fj_hmac_credential_t;

/* Caller generates a fresh unique nonce and credential ID, and must protect
 * the root according to its selected policy. Output is unchanged on failure. */
bool fj_hmac_credential_seal(fj_hmac_credential_t *record,
                             const uint8_t root[32],
                             const uint8_t material[FJ_HMAC_MATERIAL_LEN]);
/* Failure clears the plaintext output. */
bool fj_hmac_credential_open(const fj_hmac_credential_t *record,
                             const uint8_t root[32],
                             uint8_t material[FJ_HMAC_MATERIAL_LEN]);
#endif
