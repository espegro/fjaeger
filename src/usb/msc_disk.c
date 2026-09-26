/*
 * Fjaeger - encrypted MSC drive backed by on-board flash.
 *
 * Presents a FAT16 volume backed by a dedicated partition in the on-board
 * 16 MB flash. Every 512-byte sector is encrypted with AES-128-XTS using a
 * permanent disk key (independent of the key slots) and the sector LBA as
 * the tweak. While the device is LOCKED the volume reports NOT_READY so the
 * host cannot mount it; the raw (encrypted) sectors remain in flash.
 *
 * The disk key is stored in the same flash store as the PIN/slots/CTAP2
 * records, so changing or erasing key slots no longer affects disk data.
 */
#include "tusb.h"

#include "msc_disk.h"
#include "keys.h"
#include "crypto.h"
#include "state.h"
#include "rgb_led.h"

#include "hardware/flash.h"
#include "hardware/sync.h"
#include "pico/time.h"

#if CFG_TUD_MSC

#define DISK_SECTOR_SIZE       512
#define DISK_BLOCK_SIZE        FLASH_SECTOR_SIZE   /* 4096 */
#define DISK_SECTORS_PER_BLOCK (DISK_BLOCK_SIZE / DISK_SECTOR_SIZE) /* 8 */

/* Partition: 12 MiB starting 1 MiB in, leaving room for firmware growth and
 * the store at the very end. DISK_FLASH_START is an OFFSET from XIP_BASE
 * (0x10000000); the absolute address is XIP_BASE + DISK_FLASH_START. */
#define DISK_FLASH_START       0x00100000u         /* absolute 0x10100000 */
#define DISK_FLASH_SIZE        0x00C00000u         /* 12 MiB */

#define DISK_TOTAL_SECTORS     (DISK_FLASH_SIZE / DISK_SECTOR_SIZE)  /* 24576 */
#define DISK_TOTAL_BLOCKS      (DISK_FLASH_SIZE / DISK_BLOCK_SIZE)   /* 3072 */

/* FAT16 geometry (computed at init). */
static uint16_t fat_sectors;
static uint32_t root_dir_lba;    /* first root-directory sector */
static uint32_t data_lba;        /* first data-cluster sector */
static uint32_t total_clusters;

static bool disk_ready = false;
static bool fs_initialised = false;

/* Permanent disk key (two AES-128 keys for XTS). */
static uint8_t disk_key[FJ_AES_KEY_BYTES];

/* Deferred-write cache for one 4 KiB flash block. */
static uint8_t block_cache[DISK_BLOCK_SIZE] __attribute__((aligned(4)));
static uint32_t cache_block = 0xFFFFFFFFu;
static bool cache_valid = false;
static bool cache_dirty = false;

static void make_tweak(uint32_t lba, uint8_t tweak[16]) {
    memset(tweak, 0, 16);
    tweak[0] = (uint8_t)(lba & 0xff);
    tweak[1] = (uint8_t)((lba >> 8) & 0xff);
    tweak[2] = (uint8_t)((lba >> 16) & 0xff);
    tweak[3] = (uint8_t)((lba >> 24) & 0xff);
}

static uint32_t block_index_for_lba(uint32_t lba) {
    return lba / DISK_SECTORS_PER_BLOCK;
}

void flush_disk_cache(void);

/* Load a 4 KiB flash block into block_cache. */
static void load_block(uint32_t idx) {
    if (cache_valid && cache_block == idx) return;
    if (cache_dirty) flush_disk_cache();
    memcpy(block_cache, (const void *)(XIP_BASE + DISK_FLASH_START +
                                       idx * DISK_BLOCK_SIZE),
           DISK_BLOCK_SIZE);
    cache_block = idx;
    cache_valid = true;
    cache_dirty = false;
}

/* Decrypt sector 'lba' (present in block_cache) into out[512]. */
static bool decrypt_sector(uint32_t lba, uint8_t out[DISK_SECTOR_SIZE]) {
    uint32_t off = (lba % DISK_SECTORS_PER_BLOCK) * DISK_SECTOR_SIZE;
    uint8_t tweak[16];
    make_tweak(lba, tweak);
    memcpy(out, block_cache + off, DISK_SECTOR_SIZE);
    return fj_xts_sector(disk_key, tweak, out, false);
}

/* Encrypt sector 'lba' from in[512] into the current position in block_cache
 * and mark the block dirty. */
static bool encrypt_sector_into_cache(uint32_t lba, const uint8_t in[DISK_SECTOR_SIZE]) {
    uint32_t off = (lba % DISK_SECTORS_PER_BLOCK) * DISK_SECTOR_SIZE;
    uint8_t tmp[DISK_SECTOR_SIZE];
    uint8_t tweak[16];
    make_tweak(lba, tweak);
    memcpy(tmp, in, DISK_SECTOR_SIZE);
    if (!fj_xts_sector(disk_key, tweak, tmp, true)) return false;
    memcpy(block_cache + off, tmp, DISK_SECTOR_SIZE);
    cache_dirty = true;
    return true;
}

/* Persist block_cache to flash if dirty. */
void flush_disk_cache(void) {
    if (!cache_valid || !cache_dirty) return;
    uint32_t offset = DISK_FLASH_START + cache_block * DISK_BLOCK_SIZE;
    uint32_t ints = save_and_disable_interrupts();
    flash_range_erase(offset, DISK_BLOCK_SIZE);
    flash_range_program(offset, block_cache, DISK_BLOCK_SIZE);
    restore_interrupts(ints);
    cache_dirty = false;
}

/* --- FAT16 image generation ------------------------------------------ */

/* Build the clear-text content of disk sector 'lba' (0 <= lba < total). */
static void build_clear_sector(uint32_t lba, uint8_t out[DISK_SECTOR_SIZE]) {
    memset(out, 0, DISK_SECTOR_SIZE);

    if (lba == 0) {
        /* Boot sector. */
        out[0] = 0xEB; out[1] = 0x3C; out[2] = 0x90;
        memcpy(out + 3, "FJAEGER ", 8);
        out[11] = 0x00; out[12] = 0x02;              /* bytes/sector = 512 */
        out[13] = 1;                                 /* sectors/cluster = 1 */
        out[14] = 1;                                 /* reserved = 1 */
        out[16] = 2;                                 /* number of FATs */
        out[17] = 0x00; out[18] = 0x02;              /* root entries = 512 */
        out[19] = 0x00; out[20] = 0x00;              /* 16-bit total = 0 */
        out[21] = 0xF8;                              /* media */
        out[22] = (uint8_t)(fat_sectors & 0xff);
        out[23] = (uint8_t)(fat_sectors >> 8);       /* FAT size (16-bit) */
        out[24] = 0x00; out[25] = 0x00;              /* sect/track */
        out[26] = 0x00; out[27] = 0x00;              /* heads */
        out[28] = 0x00; out[29] = 0x00; out[30] = 0x00; out[31] = 0x00; /* hidden */
        out[32] = (uint8_t)(DISK_TOTAL_SECTORS & 0xff);
        out[33] = (uint8_t)((DISK_TOTAL_SECTORS >> 8) & 0xff);
        out[34] = (uint8_t)((DISK_TOTAL_SECTORS >> 16) & 0xff);
        out[35] = (uint8_t)((DISK_TOTAL_SECTORS >> 24) & 0xff); /* 32-bit total */
        out[36] = 0x80;                              /* drive number */
        out[37] = 0x00;                              /* reserved */
        out[38] = 0x29;                              /* boot signature */
        out[39] = 0x12; out[40] = 0x34; out[41] = 0x56; out[42] = 0x78; /* serial */
        memcpy(out + 43, "FJAEGER DISK ", 12);       /* volume label */
        memcpy(out + 54, "FAT16   ", 8);             /* FAT type */
        out[510] = 0x55; out[511] = 0xAA;
    } else if (lba >= 1 && lba < 1u + 2u * fat_sectors) {
        /* FAT region: entries. */
        uint32_t fat_lba = lba - 1;
        uint32_t base_entry = (fat_lba * DISK_SECTOR_SIZE) / 2;
        if (base_entry == 0) {
            out[0] = 0xF8; out[1] = 0xFF;            /* FAT[0] media */
            out[2] = 0xFF; out[3] = 0xFF;            /* FAT[1] EOC */
        }
    }
    /* root directory (root_dir_lba .. data_lba-1) and data are all zero. */
}

/* Encrypt and write the filesystem metadata (boot sector, both FATs, root
 * directory) into the flash partition. The data region is left erased
 * (0xFF) and is written lazily on demand, so first-boot initialisation is
 * fast instead of erasing the whole 12 MiB. */
static void init_filesystem(void) {
    uint32_t metadata_end_block = (data_lba + DISK_SECTORS_PER_BLOCK - 1) /
                                  DISK_SECTORS_PER_BLOCK;
    if (metadata_end_block > DISK_TOTAL_BLOCKS)
        metadata_end_block = DISK_TOTAL_BLOCKS;

    for (uint32_t idx = 0; idx < metadata_end_block; idx++) {
        uint32_t base_lba = idx * DISK_SECTORS_PER_BLOCK;
        for (uint32_t s = 0; s < DISK_SECTORS_PER_BLOCK; s++) {
            uint32_t lba = base_lba + s;
            if (lba >= DISK_TOTAL_SECTORS) break;
            uint8_t clear[DISK_SECTOR_SIZE];
            uint8_t tmp[DISK_SECTOR_SIZE];
            uint8_t tweak[16];
            build_clear_sector(lba, clear);
            make_tweak(lba, tweak);
            memcpy(tmp, clear, DISK_SECTOR_SIZE);
            if (!fj_xts_sector(disk_key, tweak, tmp, true)) return;
            memcpy(block_cache + s * DISK_SECTOR_SIZE, tmp, DISK_SECTOR_SIZE);
        }
        uint32_t offset = DISK_FLASH_START + idx * DISK_BLOCK_SIZE;
        uint32_t ints = save_and_disable_interrupts();
        flash_range_erase(offset, DISK_BLOCK_SIZE);
        flash_range_program(offset, block_cache, DISK_BLOCK_SIZE);
        restore_interrupts(ints);
    }
    cache_block = 0xFFFFFFFFu;
    cache_valid = false;
    cache_dirty = false;
}

/* Compute FAT16 geometry for the fixed partition size. */
static void compute_geometry(void) {
    /* Start with a guess and iterate to convergence. */
    uint32_t reserved = 1;
    uint32_t root_sectors = 32; /* 512 entries */
    uint32_t fats = 2;
    uint32_t fat_sz = 1;
    for (int iter = 0; iter < 16; iter++) {
        uint32_t data = DISK_TOTAL_SECTORS - reserved - fats * fat_sz - root_sectors;
        uint32_t clusters = data; /* spc = 1 */
        uint32_t needed = (clusters + 2) * 2;
        uint32_t new_fat = (needed + DISK_SECTOR_SIZE - 1) / DISK_SECTOR_SIZE;
        if (new_fat == fat_sz) break;
        fat_sz = new_fat;
    }
    fat_sectors = (uint16_t)fat_sz;
    root_dir_lba = reserved + fats * fat_sectors;
    data_lba = root_dir_lba + 32;
    total_clusters = DISK_TOTAL_SECTORS - data_lba;
}

/* Returns true if the partition appears uninitialised: the boot sector
 * block is still erased (all 0xFF). */
static bool partition_is_empty(void) {
    const uint8_t *p = (const uint8_t *)(XIP_BASE + DISK_FLASH_START);
    for (uint32_t i = 0; i < DISK_BLOCK_SIZE; i++) {
        if (p[i] != 0xFF) return false;
    }
    return true;
}

/* Decrypt the boot sector and check its 0x55 0xAA signature. */
static bool boot_sector_valid(void) {
    load_block(0);
    uint8_t boot[DISK_SECTOR_SIZE];
    if (!decrypt_sector(0, boot)) return false;
    return boot[510] == 0x55 && boot[511] == 0xAA;
}

/* ------------------------------------------------------------------ */
/* Public API                                                          */
/* ------------------------------------------------------------------ */
void fj_msc_init(void) {
    /* Ensure a permanent disk key exists (store write; safe in init). */
    if (!fj_keys_get_disk_key(disk_key)) {
        fj_random(disk_key, sizeof(disk_key));
        fj_keys_set_disk_key(disk_key);
    }

    compute_geometry();
    disk_ready = false;
}

void fj_msc_task(void) {
    /* One-time filesystem initialisation, deferred out of startup so the
     * device always enumerates even if the partition needs (re)building. */
    if (!fs_initialised) {
        if (partition_is_empty() || !boot_sector_valid()) {
            init_filesystem();
        }
        fs_initialised = true;
        return;
    }
    flush_disk_cache();
}

void tud_msc_inquiry_cb(uint8_t lun, uint8_t vendor_id[8],
                        uint8_t product_id[16], uint8_t product_rev[4]) {
    (void)lun;
    const char vid[] = "Fjaeger";
    const char pid[] = "Encrypted Drive";
    const char rev[] = "1.0";
    memcpy(vendor_id, vid, strlen(vid));
    memcpy(product_id, pid, strlen(pid));
    memcpy(product_rev, rev, strlen(rev));
}

bool tud_msc_test_unit_ready_cb(uint8_t lun) {
    (void)lun;
    if (!disk_ready || fj_state_get() != FJ_STATE_UNLOCKED || !fs_initialised) {
        /* Report "media not present" until the device is unlocked. */
        tud_msc_set_sense(lun, SCSI_SENSE_NOT_READY, 0x3a, 0x00);
        return false;
    }
    return true;
}

void tud_msc_capacity_cb(uint8_t lun, uint32_t *block_count, uint16_t *block_size) {
    (void)lun;
    *block_count = DISK_TOTAL_SECTORS;
    *block_size  = DISK_SECTOR_SIZE;
}

bool tud_msc_start_stop_cb(uint8_t lun, uint8_t power_condition,
                           bool start, bool load_eject) {
    (void)lun;
    (void)power_condition;
    if (load_eject && !start) {
        /* unload */
        disk_ready = false;
    } else {
        fj_msc_set_ready(start);
    }
    return true;
}

int32_t tud_msc_read10_cb(uint8_t lun, uint32_t lba, uint32_t offset,
                          void *buffer, uint32_t bufsize) {
    (void)lun;
    if (!disk_ready || fj_state_get() != FJ_STATE_UNLOCKED) return -1;
    if (lba >= DISK_TOTAL_SECTORS || offset > DISK_SECTOR_SIZE ||
        bufsize > DISK_SECTOR_SIZE - offset) return -1;

    fj_led_activity();
    load_block(block_index_for_lba(lba));
    uint8_t sector[DISK_SECTOR_SIZE];
    if (!decrypt_sector(lba, sector)) return -1;
    memcpy(buffer, sector + offset, bufsize);
    return (int32_t)bufsize;
}

bool tud_msc_is_writable_cb(uint8_t lun) {
    (void)lun;
    /* Writes only allowed while unlocked. */
    return fj_state_get() == FJ_STATE_UNLOCKED;
}

int32_t tud_msc_write10_cb(uint8_t lun, uint32_t lba, uint32_t offset,
                           uint8_t *buffer, uint32_t bufsize) {
    (void)lun;
    if (!disk_ready || fj_state_get() != FJ_STATE_UNLOCKED) return -1;
    if (lba >= DISK_TOTAL_SECTORS || offset > DISK_SECTOR_SIZE ||
        bufsize > DISK_SECTOR_SIZE - offset) return -1;

    fj_led_activity();
    load_block(block_index_for_lba(lba));

    /* Decrypt the target sector, patch, re-encrypt into the cache. */
    uint8_t sector[DISK_SECTOR_SIZE];
    if (!decrypt_sector(lba, sector)) return -1;
    memcpy(sector + offset, buffer, bufsize);
    if (!encrypt_sector_into_cache(lba, sector)) return -1;

    return (int32_t)bufsize;
}

int32_t tud_msc_scsi_cb(uint8_t lun, uint8_t const scsi_cmd[16],
                        void *buffer, uint16_t bufsize) {
    (void)lun;
    (void)scsi_cmd;
    (void)buffer;
    (void)bufsize;
    return 0;
}

/* Exposed to the console to mount/unmount the volume on unlock/lock. */
void fj_msc_set_ready(bool ready) {
    disk_ready = ready && fj_state_get() == FJ_STATE_UNLOCKED && fs_initialised;
}

#endif /* CFG_TUD_MSC */