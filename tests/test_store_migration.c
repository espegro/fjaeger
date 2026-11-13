/* Exercise migration and interrupted A/B writes against simulated flash. */
#include <assert.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include "hardware/flash.h"
_Alignas(4) uint8_t test_flash[PICO_FLASH_SIZE_BYTES];
static bool fail_program;
void flash_range_erase(uint32_t offset, size_t count) {
    assert(offset + count <= sizeof(test_flash));
    memset(test_flash + offset, 0xff, count);
}
void flash_range_program(uint32_t offset, const uint8_t *data, size_t count) {
    assert(offset + count <= sizeof(test_flash));
    if (fail_program) count = 64;
    memcpy(test_flash + offset, data, count);
}
#include "../src/core/keys.c"

static void make_legacy(void) {
    fj_store_record_v16_t r = {0};
    r.magic = STORE_MAGIC; r.version = LEGACY_STORE_VERSION;
    r.generation = 19; r.payload_size = sizeof(r.payload);
    r.payload.profiles[0].in_use = true;
    strcpy(r.payload.profiles[0].name, "Default");
    r.payload.profiles[1].in_use = true;
    strcpy(r.payload.profiles[1].name, "Example");
    r.payload.active_profile_valid = 1; r.payload.active_profile = 1;
    r.payload.ctap2[11].in_use = true; r.payload.ctap2[11].profile_id = 1;
    r.payload.ctap2[11].credential_id[0] = 0x57;
    r.payload.ctap2[11].private_key_enc[0] = 0x86;
    r.payload.disk_secret_enc[0] = 0x47;
    r.payload.ctap2_verifier[0] = 0x63;
    r.payload.ctap2_pin_configured = 1;
    r.payload.pass_fail = 2; r.payload.m_enc_pin[0] = 0xa9;
    r.payload.m_configured = 1;
    r.payload.timeout_configured = 0x81; r.payload.timeout_sec = 1234;
    const uint8_t *begin = (const uint8_t *)&r.version;
    const uint8_t *end = (const uint8_t *)&r.crc32;
    r.crc32 = crc32_update(0xffffffffu, begin, (size_t)(end-begin)) ^ 0xffffffffu;
    memcpy(test_flash + LEGACY_STORE_OFFSET, &r, sizeof(r));
}
int main(void) {
    memset(test_flash, 0xff, sizeof(test_flash));
    make_legacy();
    fail_program = true;
    fj_keys_init();
    assert(!store_loaded);
    assert(legacy_valid((const void *)(test_flash + LEGACY_STORE_OFFSET)));
    fail_program = false;
    fj_keys_init();
    assert(store_loaded && fj_keys_active_profile() == 1);
    assert(strcmp(fj_keys_profile_get(1)->name, "Example") == 0);
    assert(store.ctap2[11].in_use && store.ctap2[11].credential_id[0] == 0x57);
    assert(store.ctap2[11].private_key_enc[0] == 0x86);
    assert(store.disk_secret_enc[0] == 0x47 && store.ctap2_verifier[0] == 0x63);
    assert(store.pass_fail == 2 && store.m_enc_pin[0] == 0xa9);
    assert(fj_keys_presence_button() && store.timeout_sec == 1234);
    for (size_t i = LEGACY_STORE_OFFSET; i < PICO_FLASH_SIZE_BYTES; i++) assert(test_flash[i] == 0xff);
    assert(fj_keys_profile_create(15, "Extra"));
    store.ctap2[63].in_use = true; store.ctap2[63].credential_id[0] = 0x44;
    assert(fj_keys_flush());
    fj_keys_init();
    assert(fj_keys_profile_get(15) && store.ctap2[63].credential_id[0] == 0x44);
    /* Fail the inactive slot's next write: the current generation survives. */
    fail_program = true; assert(!fj_keys_set_presence_button(false));
    fail_program = false; fj_keys_init();
    assert(fj_keys_presence_button() && store.ctap2[63].credential_id[0] == 0x44);
    static fj_ctap2_cred_t all[FJ_CTAP2_CREDS];
    for (unsigned i = 0; i < FJ_CTAP2_CREDS; i++) {
        all[i].in_use = true;
        all[i].credential_id[0] = (uint8_t)i;
        all[i].profile_id = (uint8_t)(i % FJ_NUM_PROFILES);
    }
    assert(fj_keys_ctap2_save(all));
    fj_keys_init();
    for (unsigned i = 0; i < FJ_CTAP2_CREDS; i++)
        assert(store.ctap2[i].in_use && store.ctap2[i].credential_id[0] == i);
    fj_store_begin();
    assert(fj_keys_set_presence_button(false));
    fail_program = true;
    assert(!fj_store_commit());
    fail_program = false;
    assert(fj_keys_presence_button());
    fj_keys_wipe();
    for (size_t i = FLASH_OFFSET_BYTES; i < PICO_FLASH_SIZE_BYTES; i++) assert(test_flash[i] == 0xff);
    test_flash[FLASH_OFFSET_BYTES] = 0; /* Not an erased or readable store. */
    fj_keys_init();
    assert(!fj_keys_ready() && test_flash[FLASH_OFFSET_BYTES] == 0);
    puts("v16 migration, expanded store and interrupted writes: ok");
}
