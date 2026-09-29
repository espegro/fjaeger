/*
 * Fjaeger - profiles and persisted state.
 *
 * The device organises its CTAP2 credentials into named profiles. A
 * profile is metadata plus an access filter: each credential keeps its own
 * random P-256 scalar or Ed25519 seed, credential-ID and RP binding, and is
 * associated with exactly one profile. Only credentials in the active
 * profile can be enrolled or used for signing.
 *
 * The store also holds the device PIN, the MSC disk secret, brute-force
 * protection state, the recovery PUK and the auto-lock timeout. The PIN,
 * PUK and disk are shared across all profiles.
 */
#ifndef FJAEGER_KEYS_H
#define FJAEGER_KEYS_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define FJ_NUM_PROFILES   8
#define FJ_PROFILE_NAME_MAX 32
#define FJ_ECDSA_KEY_BYTES 32   /* private scalar for P-256 */
#define FJ_AES_KEY_BYTES   32   /* two AES-128 keys for XTS */

/* Slow, salted PBKDF2-HMAC-SHA256 is used to derive the device PIN, disk PIN
 * and PUK from the passphrase, so a dumped flash store cannot be brute-forced
 * offline with a fast hash. */
#define FJ_PBKDF2_ITERATIONS 100000u
#define FJ_PIN_SALT_LEN      16
#define FJ_PUK_SALT_LEN      16

/* Brute-force protection: after FJ_MAX_PIN_FAILS wrong PIN attempts a PIN
 * becomes BLOCKED and a PUK is required. After FJ_MAX_PUK_FAILS wrong PUK
 * attempts the device wipes itself (all profiles, credentials, the disk
 * secret and the PIN) — a full factory reset. */
#define FJ_MAX_PASS_FAILS 5
#define FJ_MAX_PIN_FAILS  5
#define FJ_MAX_PUK_FAILS  5

/* CTAP2 credential store size. */
#define FJ_CTAP2_CREDS     12
#define FJ_CRED_ID_LEN     16
#define FJ_USER_ID_LEN     32
#define FJ_RP_MAX          64

/* A CTAP2 (WebAuthn / sk-ecdsa) credential persisted in flash. Each
 * credential belongs to a profile (profile_id) but owns its own random
 * private key. Resident (discoverable) credentials additionally store the
 * relying-party id in clear text, a user id and the resident flag so the
 * authenticator can discover them by RP without an allowList.
 *
 * The private key is stored AES-256-GCM-encrypted at rest, wrapped by the
 * device credential wrapping key (CWK). Only the ciphertext, per-credential
 * nonce and tag are persisted; the plaintext scalar exists only transiently
 * in RAM while the device is unlocked. The public key is stored alongside so
 * credential management and discovery can expose it without decrypting. */
typedef struct {
    uint8_t credential_id[FJ_CRED_ID_LEN];
    uint8_t private_key_enc[FJ_ECDSA_KEY_BYTES]; /* GCM(cwk, key) */
    uint8_t private_key_nonce[12];
    uint8_t private_key_tag[16];
    uint8_t public_key[65];               /* P-256: 0x04||X||Y; Ed25519: 0xed||X */
    uint8_t rp_id_hash[32];               /* SHA-256 of the relying-party id */
    uint8_t rp[FJ_RP_MAX];                /* relying-party id in clear text */
    uint8_t rp_len;
    uint8_t user_id[FJ_USER_ID_LEN];
    uint8_t user_id_len;
    uint8_t profile_id;                   /* owning profile (0..FJ_NUM_PROFILES-1) */
    bool    resident;                     /* discoverable credential */
    bool    in_use;
} fj_ctap2_cred_t;

/* A named profile. A profile is metadata plus an access filter; it holds no
 * shared key material. */
typedef struct {
    char name[FJ_PROFILE_NAME_MAX];
    bool in_use;
} fj_profile_t;

/* Initialise the key store. Loads the persisted state from flash (if
 * present). On an empty store it creates profile 0 named "Default" and
 * selects it, then persists. The selected profile is loaded from flash; if
 * it no longer exists it falls back to profile 0. */
void fj_keys_init(void);

/* Number of profiles that exist. */
unsigned fj_keys_profile_count(void);

/* Get a read-only pointer to profile n. Returns NULL if n is out of range
 * or the profile does not exist. */
const fj_profile_t *fj_keys_profile_get(unsigned profile);

/* Create a new, empty profile with the given name. Rejects an ID that is
 * out of range or already in use. Returns true on success. */
bool fj_keys_profile_create(unsigned profile, const char *name);

/* Select and persist the active profile. Rejects an unknown ID. Returns
 * true on success. */
bool fj_keys_profile_select(unsigned profile);

/* Rename profile n without changing its credentials. Returns true on
 * success. */
bool fj_keys_profile_rename(unsigned profile, const char *name);

/* Erase profile n and every credential bound to it. Rejects the active
 * profile (so at least one profile always remains and the active profile
 * stays valid). Returns true on success. */
bool fj_keys_profile_erase(unsigned profile);

/* Active (currently selected) profile index. */
unsigned fj_keys_active_profile(void);

/* Persist the whole store to flash. */
bool fj_keys_flush(void);

/* Group multiple store updates into one atomic A/B flash commit (FJ-005), so
 * a power loss cannot leave a half-updated security state. Call begin(),
 * make the individual fj_keys_set_*() updates, then commit(); abort() discards
 * the pending changes without writing. */
void fj_store_begin(void);
bool fj_store_commit(void);
void fj_store_abort(void);

/* Persist the device unlock passphrase as a salted PBKDF2-HMAC-SHA256 hash.
 * The passphrase protects the master key M; it is independent of the CTAP2
 * PIN. */
bool fj_keys_set_passphrase(const uint8_t pbkdf2_hash[32], const uint8_t salt[16]);
bool fj_keys_passphrase_configured(void);
void fj_keys_get_passphrase(uint8_t pbkdf2_hash[32], uint8_t salt[16]);

/* Persist the CTAP2 client PIN, stored as LEFT(SHA-256(pin),16) — the CTAP2
 * PIN protocol only transmits that value. The CTAP2 PIN does NOT protect M,
 * so a fast offline brute-force of it yields at most a pinUvAuthToken. */
bool fj_keys_set_ctap2_pin(const uint8_t verifier[16]);
bool fj_keys_ctap2_pin_configured(void);
void fj_keys_get_ctap2_pin(uint8_t verifier[16]);

/* The MSC drive's secret is a random AES-XTS key protected with authenticated
 * key wrapping (AES-256-GCM) keyed by PBKDF2(disk PIN). These accessors
 * read/write the stored ciphertext, its KDF salt, nonce and GCM tag. See
 * msc_disk.c for the wrap/unwrap. */
bool fj_keys_disk_secret_set(void);
void fj_keys_get_disk_secret(uint8_t enc[32], uint8_t salt[16],
                             uint8_t nonce[12], uint8_t tag[16]);
bool fj_keys_set_disk_secret(const uint8_t enc[32], const uint8_t salt[16],
                             const uint8_t nonce[12], const uint8_t tag[16]);

/* The master key M protects every CTAP2 credential private key at rest. M is
 * a random 32-byte key wrapped independently by the device PIN and by the
 * recovery PUK (each with its own salt), so either secret can recover M and
 * decrypt the keys. Only the two wrapped forms and their salts are persisted;
 * the plaintext M is held in RAM only while the device is unlocked (see
 * state.c). */
bool fj_keys_master_key_set(void);
bool fj_keys_set_master_pin_wrap(const uint8_t enc[32], const uint8_t salt[16]);
bool fj_keys_get_master_pin_wrap(uint8_t enc[32], uint8_t salt[16]);
bool fj_keys_set_master_puk_wrap(const uint8_t enc[32], const uint8_t salt[16]);
bool fj_keys_get_master_puk_wrap(uint8_t enc[32], uint8_t salt[16]);

/* Brute-force protection state for the device PIN, disk PIN and PUK. */
/* Brute-force protection state. The unlock passphrase and the CTAP2 PIN are
 * independent retry domains: failing the CTAP2 PIN cannot consume the retry
 * budget of the (higher-value) unlock passphrase, and vice versa. */
typedef struct {
    uint8_t pass_fail;        /* consecutive wrong unlock-passphrase attempts */
    uint8_t pass_blocked;     /* unlock passphrase blocked, PUK required */
    uint8_t ctap_pin_fail;    /* consecutive wrong CTAP2 PIN attempts */
    uint8_t ctap_pin_blocked; /* CTAP2 PIN blocked, PUK required */
    uint8_t disk_fail;        /* consecutive wrong disk-PIN attempts */
    uint8_t disk_blocked;     /* disk PIN blocked, PUK required */
    uint8_t puk_fail;         /* consecutive wrong PUK attempts */
} fj_security_t;

/* Read/write the brute-force protection state in one flash write. */
bool fj_keys_get_security(fj_security_t *sec);
bool fj_keys_set_security(const fj_security_t *sec);

/* The recovery PUK (a long code) stored as a salted PBKDF2-HMAC-SHA256. */
bool fj_keys_puk_configured(void);
bool fj_keys_set_puk(const uint8_t pbkdf2_hash[32], const uint8_t salt[16]);
bool fj_keys_get_puk(uint8_t pbkdf2_hash[32], uint8_t salt[16]);

/* Persistent auto-lock override. Returns false when no explicit TIMEOUT has
 * been stored, in which case the state layer uses its 15-minute default. */
bool fj_keys_get_timeout(uint32_t *seconds);
bool fj_keys_set_timeout(uint32_t seconds);

/* Factory reset: erase every profile, credential, the disk secret and the
 * PIN. After this the device is fully unprovisioned; the next boot creates
 * a fresh "Default" profile. The (encrypted) disk data becomes
 * unrecoverable because its wrapping key is destroyed. */
void fj_keys_wipe(void);

/* Load all persisted CTAP2 credentials into 'out' (FJ_CTAP2_CREDS
 * entries). Returns true on success. */
void fj_keys_ctap2_load(fj_ctap2_cred_t *out);

/* Persist the full CTAP2 credential table to flash. Returns true on
 * success. */
bool fj_keys_ctap2_save(const fj_ctap2_cred_t *creds);

/* Backup / restore of the master key and the credential/profile store.
 * Used by the BACKUP/RESTORE console commands. */
typedef struct {
    uint8_t master[FJ_AES_KEY_BYTES];   /* plaintext M (decrypts the keys) */
    fj_ctap2_cred_t ctap2[FJ_CTAP2_CREDS];
    fj_profile_t profiles[FJ_NUM_PROFILES];
    uint8_t active_profile;
    uint8_t active_profile_valid;
} fj_backup_payload_t;

/* Fill the credential/profile/active-profile fields of 'out' from the
 * persistent store. 'master' is filled by the caller (state.c) from the
 * live master key. Returns true on success. */
bool fj_keys_backup_fill(fj_backup_payload_t *out);

/* Restore the credential/profile/active-profile fields from 'in' into the
 * persistent store in one write. 'master' is handled by state.c (wrapped by
 * a subsequently set PIN). Returns true on success. */
bool fj_keys_backup_restore(const fj_backup_payload_t *in);

/* Fill buf with 'len' random bytes from the hardware RNG. */
void fj_random(void *buf, size_t len);

#ifdef __cplusplus
}
#endif

#endif /* FJAEGER_KEYS_H */
