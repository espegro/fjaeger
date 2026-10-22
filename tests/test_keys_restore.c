#include <assert.h>
#include <stdio.h>
#include <string.h>
#include "keys.h"
#include "hardware/flash.h"

_Alignas(4) uint8_t test_flash[PICO_FLASH_SIZE_BYTES];
void flash_range_erase(uint32_t offset, size_t count) {
    assert(offset + count <= sizeof(test_flash));
    memset(test_flash + offset, 0xff, count);
}
void flash_range_program(uint32_t offset, const uint8_t *data, size_t count) {
    assert(offset + count <= sizeof(test_flash));
    memcpy(test_flash + offset, data, count);
}
int main(void) {
    memset(test_flash, 0xff, sizeof(test_flash));
    fj_keys_init();
    assert(fj_keys_profile_create(1, "Restored"));
    assert(fj_keys_profile_select(1));
    fj_backup_payload_t backup = {0};
    assert(fj_keys_backup_fill(&backup));
    assert(fj_keys_profile_select(0));
    fj_store_begin();
    assert(fj_keys_backup_restore(&backup));
    assert(fj_keys_active_profile() == 0);
    fj_store_abort();
    assert(fj_keys_active_profile() == 0);
    fj_backup_payload_t after = {0};
    assert(fj_keys_backup_fill(&after));
    assert(after.active_profile == 0);
    fj_store_begin();
    assert(fj_keys_backup_restore(&backup));
    assert(fj_keys_active_profile() == 0);
    assert(fj_store_commit());
    assert(fj_keys_active_profile() == 1);
    fj_keys_init();
    assert(fj_keys_active_profile() == 1);
    assert(fj_keys_profile_select(0));
    assert(fj_keys_backup_restore(&backup));
    assert(fj_keys_active_profile() == 1);
    backup.active_profile = FJ_NUM_PROFILES;
    assert(!fj_keys_backup_restore(&backup));
    assert(fj_keys_active_profile() == 1);
    backup.active_profile = 2;
    assert(!fj_keys_backup_restore(&backup));
    puts("keys restore profile/transaction tests: ok");
}
