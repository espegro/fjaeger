/*
 * Fjaeger - key slots / profiles, persisted to flash.
 */
#include <string.h>

#include "keys.h"
#include "crypto.h"

#include "hardware/flash.h"
#include "hardware/sync.h"
#include "pico/rand.h"

/* Two independent 4 KiB sectors at the end of flash form an A/B store.
 * Each update erases and programs only the older copy. A generation number
 * and CRC select the newest complete record after a reset or power loss. */
#define STORE_MAGIC   0x464A5345u /* "FJSE" */
#define STORE_VERSION 2u
#define FLASH_OFFSET_BYTES (PICO_FLASH_SIZE_BYTES - (2 * FLASH_SECTOR_SIZE))

typedef struct {
    uint8_t  pin_hash[32];
    fj_slot_t slots[FJ_NUM_SLOTS];
    fj_ctap2_cred_t ctap2[FJ_CTAP2_CREDS];
} fj_store_payload_t;

typedef struct {
    uint32_t magic;
    uint32_t version;
    uint32_t generation;
    uint32_t payload_size;
    fj_store_payload_t payload;
    uint32_t crc32;
} fj_store_record_t;

/* Original on-flash format, accepted once for a non-destructive migration. */
typedef struct {
    uint32_t magic;
    uint32_t version;
    fj_store_payload_t payload;
} fj_store_v1_t;

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

/* In-RAM shadow of the active slot. */
static int active_slot = 0;

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

    /* Migrate the original single-copy version if one was written. */
    const fj_store_v1_t *legacy = (const fj_store_v1_t *)
        (XIP_BASE + FLASH_OFFSET_BYTES);
    if (legacy->magic == STORE_MAGIC && legacy->version == 1) {
        memcpy(&store, &legacy->payload, sizeof(store));
        active_copy = 0;
    } else {
        memset(&store, 0, sizeof(store));
        active_copy = -1;
    }
    active_generation = 0;
    store_loaded = true;
}

void fj_keys_init(void) {
    load_from_flash();
    active_slot = 0;
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

bool fj_keys_flush(void) {
    return write_store();
}

void fj_keys_ctap2_load(fj_ctap2_cred_t *out) {
    memcpy(out, store.ctap2, sizeof(store.ctap2));
}

bool fj_keys_ctap2_save(const fj_ctap2_cred_t *creds) {
    memcpy(store.ctap2, creds, sizeof(store.ctap2));
    return write_store();
}

bool fj_keys_set_pin_hash(const uint8_t hash[32]) {
    memcpy(store.pin_hash, hash, 32);
    return write_store();
}

bool fj_keys_get_pin_hash(uint8_t hash[32]) {
    if (!store_loaded) return false;
    /* All-zero means unset. */
    uint8_t acc = 0;
    for (size_t i = 0; i < 32; i++) acc |= store.pin_hash[i];
    if (acc == 0) return false;
    memcpy(hash, store.pin_hash, 32);
    return true;
}

unsigned fj_keys_count(void) {
    unsigned n = 0;
    for (unsigned i = 0; i < FJ_NUM_SLOTS; i++) {
        if (store.slots[i].initialized) n++;
    }
    return n;
}

unsigned fj_keys_active_slot(void) {
    return (unsigned)active_slot;
}

bool fj_keys_set_active_slot(unsigned slot) {
    if (slot >= FJ_NUM_SLOTS) return false;
    if (!store.slots[slot].initialized) return false;
    active_slot = (int)slot;
    return true;
}

const fj_slot_t *fj_keys_get(unsigned slot) {
    if (slot >= FJ_NUM_SLOTS) return NULL;
    if (!store.slots[slot].initialized) return NULL;
    return &store.slots[slot];
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

bool fj_keys_provision(unsigned slot, const char *name, bool gen) {
    if (slot >= FJ_NUM_SLOTS) return false;

    fj_slot_t *s = &store.slots[slot];
    if (name) {
        strncpy(s->name, name, sizeof(s->name) - 1);
        s->name[sizeof(s->name) - 1] = '\0';
    }

    if (gen) {
        /* Fresh P-256 scalar + two AES-128 keys for XTS. */
        if (!fj_ecdsa_generate_private(s->private_key)) return false;
        fj_random(s->aes_key, FJ_AES_KEY_BYTES);
        s->initialized = true;
    }
    /* Imported keys are set by the caller before calling provision() with
     * gen=false; here we just mark it initialised. */
    s->initialized = true;

    return write_store();
}

bool fj_keys_erase(unsigned slot) {
    if (slot >= FJ_NUM_SLOTS) return false;
    memset(&store.slots[slot], 0, sizeof(fj_slot_t));
    return write_store();
}
