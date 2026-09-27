/*
 * Fjaeger - profiles and persisted state, stored in flash.
 */
#include <string.h>

#include "keys.h"

#include "hardware/flash.h"
#include "hardware/sync.h"
#include "pico/rand.h"

/* Two independent 4 KiB sectors at the end of flash form an A/B store.
 * Each update erases and programs only the older copy. A generation number
 * and CRC select the newest complete record after a reset or power loss. */
#define STORE_MAGIC   0x464A5345u /* "FJSE" */
#define STORE_VERSION 14u
#define FLASH_OFFSET_BYTES (PICO_FLASH_SIZE_BYTES - (2 * FLASH_SECTOR_SIZE))

typedef struct {
    /* Unlock passphrase (v14): protects the master key M. Stored as a salted
     * PBKDF2 hash. This is INDEPENDENT of the CTAP2 PIN, so a flash dump that
     * brute-forces the (fast) CTAP2 verifier cannot recover the passphrase
     * that unwraps M. */
    uint8_t  pass_hash[32];        /* PBKDF2-SHA256(passphrase, pass_salt) */
    uint8_t  pass_salt[16];
    uint8_t  pass_configured;      /* 1 once the unlock passphrase is set */
    /* CTAP2 PIN (v14): used only by the CTAP2 clientPIN protocol. Stored as
     * LEFT(SHA-256(pin),16) because the CTAP2 protocol only transmits that
     * value. It does NOT protect M, so its fast offline brute-force yields at
     * most a pinUvAuthToken, never the credential keys. */
    uint8_t  ctap2_verifier[16];
    uint8_t  ctap2_pin_configured; /* 1 once a CTAP2 PIN is set */
    fj_profile_t profiles[FJ_NUM_PROFILES];
    fj_ctap2_cred_t ctap2[FJ_CTAP2_CREDS];
    /* Disk secret (v13): the random AES-XTS disk key is protected with
     * authenticated key wrapping. K = PBKDF2(disk PIN, disk_pin_salt), then
     * disk_secret_enc, disk_wrap_tag = AES-256-GCM(K, disk_wrap_nonce,
     * disk_key). The GCM tag both authenticates the ciphertext and verifies
     * the disk PIN (a wrong PIN fails decryption). A separate verification
     * hash is deliberately NOT stored, so a flash dump cannot derive the disk
     * key (disk_secret_enc XOR hash). */
    uint8_t  disk_secret_enc[32];  /* AES-GCM ciphertext of the disk key */
    uint8_t  disk_pin_salt[16];
    uint8_t  disk_wrap_nonce[12];
    uint8_t  disk_wrap_tag[16];
    uint8_t  disk_secret_valid;    /* 1 once the disk PIN/secret are set */
    /* Brute-force protection (v5). */
    uint8_t  pin_fail;             /* wrong device-PIN attempts */
    uint8_t  pin_blocked;          /* device PIN blocked, PUK required */
    uint8_t  disk_fail;            /* wrong disk-PIN attempts */
    uint8_t  disk_blocked;         /* disk PIN blocked, PUK required */
    uint8_t  puk_hash[32];         /* recovery PUK (PBKDF2-SHA256) */
    uint8_t  puk_salt[16];
    uint8_t  puk_configured;
    uint8_t  puk_fail;             /* wrong PUK attempts */
    /* Persistent auto-lock override (v6). */
    uint32_t timeout_sec;
    uint8_t  timeout_configured;   /* distinguishes TIMEOUT 0 from default */
    /* Selected profile (v7). */
    uint8_t  active_profile;
    uint8_t  active_profile_valid;
    /* Master key M (v12): a random 32-byte master key that encrypts every
     * CTAP2 credential private key at rest. M is wrapped independently by
     * the device PIN and the recovery PUK (each with its own salt), so that
     * either one can recover M and thus decrypt the keys. This lets the PUK
     * set a new PIN without losing the keys. */
    uint8_t  m_enc_pin[32];    /* M XOR PBKDF2(PIN, m_salt_pin) */
    uint8_t  m_salt_pin[16];
    uint8_t  m_enc_puk[32];    /* M XOR PBKDF2(PUK, m_salt_puk) */
    uint8_t  m_salt_puk[16];
    uint8_t  m_configured;     /* 1 once the master key exists */
} fj_store_payload_t;

typedef struct {
    uint32_t magic;
    uint32_t version;
    uint32_t generation;
    uint32_t payload_size;
    fj_store_payload_t payload;
    uint32_t crc32;
} fj_store_record_t;

#define PROGRAM_SIZE \
    (((sizeof(fj_store_record_t) + FLASH_PAGE_SIZE - 1) / FLASH_PAGE_SIZE) * \
     FLASH_PAGE_SIZE)

_Static_assert(PROGRAM_SIZE <= FLASH_SECTOR_SIZE,
               "key store must fit in one flash sector");

static fj_store_payload_t store;
static bool store_loaded = false;
static int active_copy = -1;
static uint32_t active_generation = 0;
static uint8_t program_buf[PROGRAM_SIZE] __attribute__((aligned(4)));

/* In-RAM shadow of the active profile index. */
static int active_profile = 0;

static bool write_store(void);

static const fj_store_record_t *flash_record(unsigned copy) {
    return (const fj_store_record_t *)(XIP_BASE + FLASH_OFFSET_BYTES +
                                       copy * FLASH_SECTOR_SIZE);
}

static uint32_t crc32_update(uint32_t crc, const uint8_t *data, size_t len) {
    while (len--) {
        crc ^= *data++;
        for (unsigned bit = 0; bit < 8; bit++)
            crc = (crc >> 1) ^ (0xedb88320u & (uint32_t)-(int32_t)(crc & 1));
    }
    return crc;
}

static uint32_t record_crc(const fj_store_record_t *record) {
    const uint8_t *begin = (const uint8_t *)&record->version;
    const uint8_t *end = (const uint8_t *)&record->crc32;
    return crc32_update(0xffffffffu, begin, (size_t)(end - begin)) ^ 0xffffffffu;
}

static bool record_valid(const fj_store_record_t *record) {
    return record->magic == STORE_MAGIC &&
           record->version == STORE_VERSION &&
           record->payload_size == sizeof(record->payload) &&
           record->crc32 == record_crc(record);
}

static bool generation_newer(uint32_t a, uint32_t b) {
    return (int32_t)(a - b) > 0;
}

static void load_from_flash(void) {
    const fj_store_record_t *a = flash_record(0);
    const fj_store_record_t *b = flash_record(1);
    bool a_valid = record_valid(a);
    bool b_valid = record_valid(b);

    if (a_valid || b_valid) {
        unsigned selected = a_valid && (!b_valid || generation_newer(a->generation,
                                                                      b->generation))
                                ? 0u : 1u;
        const fj_store_record_t *record = flash_record(selected);
        memcpy(&store, &record->payload, sizeof(store));
        active_copy = (int)selected;
        active_generation = record->generation;
        store_loaded = true;
        return;
    }

    /* No migration: the flash format version was bumped and development
     * data may be lost. A fresh store is started. */
    memset(&store, 0, sizeof(store));
    active_copy = -1;
    active_generation = 0;
    store_loaded = true;
}

void fj_keys_init(void) {
    load_from_flash();
    active_profile = 0;

    /* Ensure a Default profile always exists and the active profile is
     * valid. On an empty store (or after a factory wipe) this creates and
     * persists profile 0 named "Default" and selects it. */
    bool have_profile = false;
    for (unsigned i = 0; i < FJ_NUM_PROFILES; i++) {
        if (store.profiles[i].in_use) { have_profile = true; break; }
    }
    if (!have_profile) {
        strncpy(store.profiles[0].name, "Default", sizeof(store.profiles[0].name) - 1);
        store.profiles[0].name[sizeof(store.profiles[0].name) - 1] = '\0';
        store.profiles[0].in_use = true;
        store.active_profile = 0;
        store.active_profile_valid = 1;
        active_profile = 0;
        write_store();
    } else {
        /* The persisted active profile may no longer exist (e.g. an older
         * record with a stale selection); fall back to the first profile. */
        unsigned target = store.active_profile;
        if (store.active_profile_valid && target < FJ_NUM_PROFILES &&
            store.profiles[target].in_use) {
            active_profile = (int)target;
        } else {
            active_profile = -1;
            for (unsigned i = 0; i < FJ_NUM_PROFILES; i++) {
                if (store.profiles[i].in_use) { active_profile = (int)i; break; }
            }
            if (active_profile < 0) active_profile = 0;
            store.active_profile = (uint8_t)active_profile;
            store.active_profile_valid = 1;
            write_store();
        }
    }
}

static bool write_store(void) {
    if (!store_loaded) return false;

    unsigned target = active_copy == 0 ? 1u : 0u;
    uint32_t generation = active_generation + 1;
    memset(program_buf, 0xff, sizeof(program_buf));

    fj_store_record_t *record = (fj_store_record_t *)program_buf;
    record->magic = STORE_MAGIC;
    record->version = STORE_VERSION;
    record->generation = generation;
    record->payload_size = sizeof(record->payload);
    memcpy(&record->payload, &store, sizeof(store));
    record->crc32 = record_crc(record);

    uint32_t offset = FLASH_OFFSET_BYTES + target * FLASH_SECTOR_SIZE;
    uint32_t ints = save_and_disable_interrupts();
    flash_range_erase(offset, FLASH_SECTOR_SIZE);
    flash_range_program(offset, program_buf, sizeof(program_buf));
    restore_interrupts(ints);

    active_copy = (int)target;
    active_generation = generation;
    return true;
}

/* ------------------------------------------------------------------ */
/* Store transactions (FJ-005)                                        */
/*                                                                     */
/* Several security-state updates (e.g. a passphrase change re-wraps    */
/* the master key) touch multiple store fields. Without care they        */
/* commit as several independent A/B generations; a power loss between  */
/* them can leave a partially-updated state (new verifier + old wrap).  */
/* fj_store_begin()/fj_store_commit() group such changes into ONE flash */
/* commit so the store is always either fully old or fully new.         */
/* ------------------------------------------------------------------ */
static bool store_tx = false;
static bool store_dirty = false;

/* Decide whether to write flash now (outside a transaction) or defer to a
 * later fj_store_commit(). Returns true on success (always in a tx). */
static bool store_write_commit(void) {
    if (store_tx) {
        store_dirty = true;
        return true;
    }
    return store_write_commit();
}

void fj_store_begin(void) {
    store_tx = true;
    store_dirty = false;
}

bool fj_store_commit(void) {
    bool dirty = store_dirty;
    store_tx = false;
    store_dirty = false;
    if (!dirty) return true;
    return store_write_commit();
}

void fj_store_abort(void) {
    store_tx = false;
    store_dirty = false;
}

bool fj_keys_flush(void) {
    return store_write_commit();
}

void fj_keys_ctap2_load(fj_ctap2_cred_t *out) {
    memcpy(out, store.ctap2, sizeof(store.ctap2));
}

bool fj_keys_ctap2_save(const fj_ctap2_cred_t *creds) {
    memcpy(store.ctap2, creds, sizeof(store.ctap2));
    return store_write_commit();
}

bool fj_keys_backup_fill(fj_backup_payload_t *out) {
    if (!store_loaded || !out) return false;
    memcpy(out->ctap2, store.ctap2, sizeof(out->ctap2));
    memcpy(out->profiles, store.profiles, sizeof(out->profiles));
    out->active_profile = store.active_profile;
    out->active_profile_valid = store.active_profile_valid;
    return true;
}

bool fj_keys_backup_restore(const fj_backup_payload_t *in) {
    if (!store_loaded || !in) return false;
    memcpy(store.ctap2, in->ctap2, sizeof(store.ctap2));
    memcpy(store.profiles, in->profiles, sizeof(store.profiles));
    store.active_profile = in->active_profile;
    store.active_profile_valid = in->active_profile_valid;
    return store_write_commit();
}

bool fj_keys_set_passphrase(const uint8_t pbkdf2_hash[32], const uint8_t salt[16]) {
    memcpy(store.pass_hash, pbkdf2_hash, 32);
    memcpy(store.pass_salt, salt, 16);
    store.pass_configured = 1;
    store.pin_fail = 0;
    store.pin_blocked = 0;
    return store_write_commit();
}

bool fj_keys_passphrase_configured(void) {
    return store_loaded && store.pass_configured != 0;
}

void fj_keys_get_passphrase(uint8_t pbkdf2_hash[32], uint8_t salt[16]) {
    memcpy(pbkdf2_hash, store.pass_hash, 32);
    memcpy(salt, store.pass_salt, 16);
}

bool fj_keys_set_ctap2_pin(const uint8_t verifier[16]) {
    memcpy(store.ctap2_verifier, verifier, 16);
    store.ctap2_pin_configured = 1;
    return store_write_commit();
}

bool fj_keys_ctap2_pin_configured(void) {
    return store_loaded && store.ctap2_pin_configured != 0;
}

void fj_keys_get_ctap2_pin(uint8_t verifier[16]) {
    memcpy(verifier, store.ctap2_verifier, 16);
}

bool fj_keys_disk_secret_set(void) {
    if (!store_loaded) return false;
    return store.disk_secret_valid != 0;
}

void fj_keys_get_disk_secret(uint8_t enc[32], uint8_t salt[16],
                             uint8_t nonce[12], uint8_t tag[16]) {
    memcpy(enc, store.disk_secret_enc, 32);
    memcpy(salt, store.disk_pin_salt, 16);
    memcpy(nonce, store.disk_wrap_nonce, 12);
    memcpy(tag, store.disk_wrap_tag, 16);
}

bool fj_keys_set_disk_secret(const uint8_t enc[32], const uint8_t salt[16],
                             const uint8_t nonce[12], const uint8_t tag[16]) {
    if (!store_loaded) return false;
    memcpy(store.disk_secret_enc, enc, 32);
    memcpy(store.disk_pin_salt, salt, 16);
    memcpy(store.disk_wrap_nonce, nonce, 12);
    memcpy(store.disk_wrap_tag, tag, 16);
    store.disk_secret_valid = 1;
    store.disk_fail = 0;
    store.disk_blocked = 0;
    return store_write_commit();
}

bool fj_keys_master_key_set(void) {
    if (!store_loaded) return false;
    return store.m_configured != 0;
}

bool fj_keys_set_master_pin_wrap(const uint8_t enc[32], const uint8_t salt[16]) {
    if (!store_loaded) return false;
    memcpy(store.m_enc_pin, enc, 32);
    memcpy(store.m_salt_pin, salt, 16);
    store.m_configured = 1;
    return store_write_commit();
}

bool fj_keys_get_master_pin_wrap(uint8_t enc[32], uint8_t salt[16]) {
    if (!store_loaded || !store.m_configured) return false;
    memcpy(enc, store.m_enc_pin, 32);
    memcpy(salt, store.m_salt_pin, 16);
    return true;
}

bool fj_keys_set_master_puk_wrap(const uint8_t enc[32], const uint8_t salt[16]) {
    if (!store_loaded) return false;
    memcpy(store.m_enc_puk, enc, 32);
    memcpy(store.m_salt_puk, salt, 16);
    store.m_configured = 1;
    return store_write_commit();
}

bool fj_keys_get_master_puk_wrap(uint8_t enc[32], uint8_t salt[16]) {
    if (!store_loaded || !store.m_configured) return false;
    memcpy(enc, store.m_enc_puk, 32);
    memcpy(salt, store.m_salt_puk, 16);
    return true;
}

bool fj_keys_get_security(fj_security_t *sec) {
    if (!store_loaded) return false;
    sec->pin_fail = store.pin_fail;
    sec->pin_blocked = store.pin_blocked;
    sec->disk_fail = store.disk_fail;
    sec->disk_blocked = store.disk_blocked;
    sec->puk_fail = store.puk_fail;
    return true;
}

bool fj_keys_set_security(const fj_security_t *sec) {
    if (!store_loaded) return false;
    store.pin_fail = sec->pin_fail;
    store.pin_blocked = sec->pin_blocked;
    store.disk_fail = sec->disk_fail;
    store.disk_blocked = sec->disk_blocked;
    store.puk_fail = sec->puk_fail;
    return store_write_commit();
}

bool fj_keys_puk_configured(void) {
    if (!store_loaded) return false;
    return store.puk_configured != 0;
}

bool fj_keys_set_puk(const uint8_t pbkdf2_hash[32], const uint8_t salt[16]) {
    if (!store_loaded) return false;
    memcpy(store.puk_hash, pbkdf2_hash, 32);
    memcpy(store.puk_salt, salt, 16);
    store.puk_configured = 1;
    store.puk_fail = 0;
    return store_write_commit();
}

bool fj_keys_get_puk(uint8_t pbkdf2_hash[32], uint8_t salt[16]) {
    if (!store_loaded) return false;
    if (!store.puk_configured) return false;
    memcpy(pbkdf2_hash, store.puk_hash, 32);
    memcpy(salt, store.puk_salt, 16);
    return true;
}

bool fj_keys_get_timeout(uint32_t *seconds) {
    if (!store_loaded || !store.timeout_configured || !seconds) return false;
    *seconds = store.timeout_sec;
    return true;
}

bool fj_keys_set_timeout(uint32_t seconds) {
    if (!store_loaded) return false;
    store.timeout_sec = seconds;
    store.timeout_configured = 1;
    return store_write_commit();
}

void fj_keys_wipe(void) {
    memset(&store, 0, sizeof(store));
    if (store_loaded) {
        /* A normal A/B update intentionally leaves the previous generation
         * intact. A factory wipe must instead erase both copies so secrets
         * are not recoverable merely by selecting or dumping the old one. */
        uint32_t ints = save_and_disable_interrupts();
        flash_range_erase(FLASH_OFFSET_BYTES, 2 * FLASH_SECTOR_SIZE);
        restore_interrupts(ints);
    }
    active_profile = 0;
    active_copy = -1;
    active_generation = 0;
}

unsigned fj_keys_profile_count(void) {
    unsigned n = 0;
    for (unsigned i = 0; i < FJ_NUM_PROFILES; i++) {
        if (store.profiles[i].in_use) n++;
    }
    return n;
}

unsigned fj_keys_active_profile(void) {
    return (unsigned)active_profile;
}

const fj_profile_t *fj_keys_profile_get(unsigned profile) {
    if (profile >= FJ_NUM_PROFILES) return NULL;
    if (!store.profiles[profile].in_use) return NULL;
    return &store.profiles[profile];
}

bool fj_keys_profile_create(unsigned profile, const char *name) {
    if (profile >= FJ_NUM_PROFILES) return false;
    if (store.profiles[profile].in_use) return false;
    if (!name || name[0] == '\0') return false;

    fj_profile_t *p = &store.profiles[profile];
    strncpy(p->name, name, sizeof(p->name) - 1);
    p->name[sizeof(p->name) - 1] = '\0';
    p->in_use = true;

    return store_write_commit();
}

bool fj_keys_profile_select(unsigned profile) {
    if (profile >= FJ_NUM_PROFILES) return false;
    if (!store.profiles[profile].in_use) return false;

    store.active_profile = (uint8_t)profile;
    store.active_profile_valid = 1;
    active_profile = (int)profile;
    return store_write_commit();
}

bool fj_keys_profile_rename(unsigned profile, const char *name) {
    if (profile >= FJ_NUM_PROFILES) return false;
    if (!store.profiles[profile].in_use) return false;
    if (!name || name[0] == '\0') return false;

    fj_profile_t *p = &store.profiles[profile];
    strncpy(p->name, name, sizeof(p->name) - 1);
    p->name[sizeof(p->name) - 1] = '\0';

    return store_write_commit();
}

bool fj_keys_profile_erase(unsigned profile) {
    if (profile >= FJ_NUM_PROFILES) return false;
    if (!store.profiles[profile].in_use) return false;
    /* The active profile must not be erased so the device always has a
     * valid active profile and at least one profile remains. */
    if (profile == (unsigned)active_profile) return false;

    memset(&store.profiles[profile], 0, sizeof(fj_profile_t));

    /* Remove every credential bound to the erased profile so it can never
     * be used again, now or after a reboot. */
    for (unsigned i = 0; i < FJ_CTAP2_CREDS; i++) {
        if (store.ctap2[i].in_use && store.ctap2[i].profile_id == profile)
            memset(&store.ctap2[i], 0, sizeof(fj_ctap2_cred_t));
    }

    return store_write_commit();
}

void fj_random(void *buf, size_t len) {
    uint8_t *out = (uint8_t *)buf;
    size_t done = 0;
    while (done < len) {
        uint64_t r = get_rand_64();
        size_t n = len - done;
        if (n > sizeof(r)) n = sizeof(r);
        memcpy(out + done, &r, n);
        done += n;
    }
}
