#ifndef FJ_FLASH_LAYOUT_H
#define FJ_FLASH_LAYOUT_H

/* Offsets from XIP_BASE. Keep the legacy sectors at the end of flash so
 * existing devices can migrate. All users of these reserved regions must
 * use this layout rather than maintaining independent offset arithmetic. */
#include "hardware/flash.h"

#define FJ_KEYS_SLOT_SIZE       (32u * 1024u)
#define FJ_LEGACY_STORE_OFFSET  (PICO_FLASH_SIZE_BYTES - 2u * FLASH_SECTOR_SIZE)
#define FJ_KEYS_STORE_OFFSET    (FJ_LEGACY_STORE_OFFSET - 2u * FJ_KEYS_SLOT_SIZE)
#define FJ_HMAC_STORE_OFFSET    (FJ_KEYS_STORE_OFFSET - 2u * FLASH_SECTOR_SIZE)
#define FJ_RESTORE_JOURNAL_OFFSET (FJ_HMAC_STORE_OFFSET - 2u * FLASH_SECTOR_SIZE)
#define FJ_HMAC_STAGE_OFFSET   (FJ_RESTORE_JOURNAL_OFFSET - FLASH_SECTOR_SIZE)
#define FJ_KEYS_STAGE_OFFSET   (FJ_HMAC_STAGE_OFFSET - FJ_KEYS_SLOT_SIZE)
#define FJ_HMAC_CONFIG_OFFSET  (FJ_KEYS_STAGE_OFFSET - 2u * FLASH_SECTOR_SIZE)

_Static_assert(PICO_FLASH_SIZE_BYTES >= 3u * FJ_KEYS_SLOT_SIZE + 9u * FLASH_SECTOR_SIZE,
               "flash too small for reserved stores");
_Static_assert(FJ_KEYS_SLOT_SIZE % FLASH_SECTOR_SIZE == 0,
               "key slots must contain whole sectors");
_Static_assert(FJ_HMAC_CONFIG_OFFSET % FLASH_SECTOR_SIZE == 0,
               "reserved flash regions must be sector aligned");

#endif
