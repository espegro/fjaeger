/*
 * Fjaeger - key slots / profiles.
 *
 * The device stores multiple independent key "profiles". Each profile
 * has:
 *   - an ECDSA P-256 (secp256r1) keypair used for U2F/SSH signing
 *   - two AES-128 keys used for XTS encryption of MSC blocks
 *
 * Only the active slot is used for signing and for MSC encryption.
 * Slots are selected over the serial console with "KEY SELECT <n>".
 */
#ifndef FJAEGER_KEYS_H
#define FJAEGER_KEYS_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define FJ_NUM_SLOTS       8
#define FJ_SLOT_NAME_MAX   32
#define FJ_ECDSA_KEY_BYTES 32   /* private scalar for P-256 */
#define FJ_AES_KEY_BYTES   32   /* two AES-128 keys for XTS */

/* CTAP2 credential store size. */
#define FJ_CTAP2_CREDS     8
#define FJ_CRED_ID_LEN     16
#define FJ_USER_ID_LEN     16

/* A CTAP2 (WebAuthn / sk-ecdsa) credential persisted in flash. */
typedef struct {
    uint8_t credential_id[FJ_CRED_ID_LEN];
    uint8_t private_key[FJ_ECDSA_KEY_BYTES];
    uint8_t rp_id_hash[32];           /* SHA-256 of the relying-party id */
    uint8_t user_id[FJ_USER_ID_LEN];
    uint8_t user_id_len;
    bool    in_use;
} fj_ctap2_cred_t;

typedef struct {
    uint8_t  private_key[FJ_ECDSA_KEY_BYTES]; /* raw P-256 scalar */
    uint8_t  aes_key[FJ_AES_KEY_BYTES];       /* two AES-128 XTS keys */
    char     name[FJ_SLOT_NAME_MAX];
    bool     initialized;                     /* slot has been provisioned */
} fj_slot_t;

/* Maximum number of slots is fixed at compile time. */
#define FJ_MAX_SLOTS FJ_NUM_SLOTS

/* Initialise the key store. Loads slot table from flash (if present). */
void fj_keys_init(void);

/* Number of slots that have been provisioned. */
unsigned fj_keys_count(void);

/* Active (currently selected) slot index. */
unsigned fj_keys_active_slot(void);

/* Select the active slot. Returns false if the slot is out of range or
 * not provisioned. */
bool fj_keys_set_active_slot(unsigned slot);

/* Get a pointer to slot n (read-only). Returns NULL if n out of range. */
const fj_slot_t *fj_keys_get(unsigned slot);

/* Create / overwrite slot n. Generates fresh keys if gen==true, otherwise
 * imports the given private scalar. Returns true on success. */
bool fj_keys_provision(unsigned slot, const char *name, bool gen);

/* Erase slot n. Returns true on success. */
bool fj_keys_erase(unsigned slot);

/* Persist the slot table to flash. */
bool fj_keys_flush(void);

/* Persist the PIN hash (SHA-256, 32 bytes) to flash. */
bool fj_keys_set_pin_hash(const uint8_t hash[32]);

/* Load the stored PIN hash (if any). Returns false if none is stored. */
bool fj_keys_get_pin_hash(uint8_t hash[32]);

/* The MSC drive uses its own permanent XTS key, independent of the active
 * slot. Returns true and fills 'key' (FJ_AES_KEY_BYTES) if one is stored. */
bool fj_keys_get_disk_key(uint8_t key[FJ_AES_KEY_BYTES]);

/* Persist the permanent MSC disk key to flash. */
bool fj_keys_set_disk_key(const uint8_t key[FJ_AES_KEY_BYTES]);

/* Load all persisted CTAP2 credentials into 'out' (FJ_CTAP2_CREDS
 * entries). Returns true on success. */
void fj_keys_ctap2_load(fj_ctap2_cred_t *out);

/* Persist the full CTAP2 credential table to flash. Returns true on
 * success. */
bool fj_keys_ctap2_save(const fj_ctap2_cred_t *creds);

/* Fill buf with 'len' random bytes from the hardware RNG. */
void fj_random(void *buf, size_t len);

#ifdef __cplusplus
}
#endif

#endif /* FJAEGER_KEYS_H */
