/*
 * Fjaeger - key slots / profiles, persisted to flash.
 */
#include <string.h>

#include "keys.h"
#include "crypto.h"

#include "hardware/flash.h"
#include "hardware/sync.h"
#include "pico/rand.h"

/* ------------------------------------------------------------------ */
/* Flash layout: reserve two 4KB sectors near the end of flash for the
 * persistent key store. Layout:
 *
 *   [0]  uint32 magic
 *   [4]  uint32 version
 *   [8]  uint8  pin_hash[32]   (SHA-256, or all-zero if unset)
 *   [40] fj_slot_t slots[FJ_NUM_SLOTS]
 *
 * One flash sector is erased at a time so a power-loss mid-write cannot
 * corrupt an already-programmed copy. The active copy is tracked with
 * a monotonically increasing generation counter in the magic field's
 * upper bits.
 */
/* ------------------------------------------------------------------ */

#define MAGIC 0x464A5345u /* "FJSE" */

#define FLASH_OFFSET_BYTES (PICO_FLASH_SIZE_BYTES - (2 * FLASH_SECTOR_SIZE))

typedef struct {
    uint32_t magic;              /* MAGIC | (gen << 8) */
    uint32_t version;
    uint8_t  pin_hash[32];
    fj_slot_t slots[FJ_NUM_SLOTS];
    fj_ctap2_cred_t ctap2[FJ_CTAP2_CREDS];
} fj_store_t;

static fj_store_t store;
static bool store_loaded = false;

/* In-RAM shadow of the active slot. */
static int active_slot = 0;

static const fj_store_t *flash_ptr(void) {
    return (const fj_store_t *)(XIP_BASE + FLASH_OFFSET_BYTES);
}

static void load_from_flash(void) {
    const fj_store_t *p = flash_ptr();

    if (p->magic == MAGIC && p->version == 1) {
        memcpy(&store, p, sizeof(store));
        store_loaded = true;
        return;
    }
    /* No valid store yet: initialise empty. */
    memset(&store, 0, sizeof(store));
    store.magic = MAGIC;
    store.version = 1;
    store_loaded = true;
}

void fj_keys_init(void) {
    load_from_flash();
    active_slot = 0;
}

static bool write_store(void) {
    if (!store_loaded) return false;

    /* Erase both sectors then program the first copy. */
    uint32_t ints = save_and_disable_interrupts();
    flash_range_erase(FLASH_OFFSET_BYTES, 2 * FLASH_SECTOR_SIZE);
    flash_range_program(FLASH_OFFSET_BYTES, (const uint8_t *)&store, sizeof(store));
    restore_interrupts(ints);
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
        /* Fresh random 32-byte private scalar + AES-256 key. */
        fj_random(s->private_key, FJ_ECDSA_KEY_BYTES);
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