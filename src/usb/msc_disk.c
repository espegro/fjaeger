/*
 * Fjaeger - encrypted MSC drive.
 *
 * The drive presents a small FAT12 volume. Every sector is encrypted with
 * AES-128-XTS using the active slot's XTS key and the sector LBA as the
 * tweak. While the device is LOCKED the volume reports NOT_READY so the
 * host cannot mount it; the raw (encrypted) sectors remain in RAM.
 */
#include "tusb.h"

#include "msc_disk.h"
#include "keys.h"
#include "crypto.h"
#include "state.h"
#include "rgb_led.h"

#if CFG_TUD_MSC

#define DISK_BLOCK_NUM  16   /* 8 KB - smallest size Windows will mount */
#define DISK_BLOCK_SIZE 512

/* Raw (encrypted) backing store. */
static uint8_t msc_disk[DISK_BLOCK_NUM][DISK_BLOCK_SIZE];

/* In-memory boot image is built from a clear FAT12 volume, then encrypted
 * once into msc_disk. */
static const uint8_t fat_boot[DISK_BLOCK_SIZE] = {
    0xEB, 0x3C, 0x90, 0x4D, 0x53, 0x44, 0x4F, 0x53, 0x35, 0x2E, 0x30, 0x00, 0x02, 0x01, 0x01, 0x00,
    0x01, 0x10, 0x00, 0x10, 0x00, 0xF8, 0x01, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x80, 0x00, 0x29, 0x34, 0x12, 0x00, 0x00, 'F',  'J',  'A',  'E',  'G',
    'E',  'R',  ' ',  'D',  'R',  'V',  0x46, 0x41, 0x54, 0x31, 0x32, 0x20, 0x20, 0x20, 0x00, 0x00,
    [510] = 0x55, [511] = 0xaa,
};

static bool disk_ready = false;

/* Derive a 16-byte tweak from a sector LBA. */
static void make_tweak(uint32_t lba, uint8_t tweak[16]) {
    memset(tweak, 0, 16);
    tweak[0] = (uint8_t)(lba & 0xff);
    tweak[1] = (uint8_t)((lba >> 8) & 0xff);
    tweak[2] = (uint8_t)((lba >> 16) & 0xff);
    tweak[3] = (uint8_t)((lba >> 24) & 0xff);
}

/* Encrypt the clear FAT volume into msc_disk using the active slot key.
 * Returns false if no slot is provisioned. */
static bool encrypt_disk(void) {
    const fj_slot_t *slot = fj_keys_get(fj_keys_active_slot());
    if (!slot) return false;

    uint8_t tweak[16];
    for (uint32_t lba = 0; lba < DISK_BLOCK_NUM; lba++) {
        uint8_t sector[DISK_BLOCK_SIZE];
        if (lba == 0) {
            memcpy(sector, fat_boot, DISK_BLOCK_SIZE);
        } else {
            memset(sector, 0, DISK_BLOCK_SIZE);
            if (lba == 1) {
                sector[0] = 0xf8;
                sector[1] = 0xff;
                sector[2] = 0xff;
            }
        }
        make_tweak(lba, tweak);
        if (!fj_xts_sector(slot->aes_key, tweak, sector, true)) return false;
        memcpy(msc_disk[lba], sector, DISK_BLOCK_SIZE);
    }
    return true;
}

/* Called once from the app to prepare the (encrypted) backing store. */
void fj_msc_init(void) {
    encrypt_disk();
    disk_ready = false;
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
    if (!disk_ready || fj_state_get() != FJ_STATE_UNLOCKED) {
        /* Report "media not present" until the device is unlocked. */
        tud_msc_set_sense(lun, SCSI_SENSE_NOT_READY, 0x3a, 0x00);
        return false;
    }
    return true;
}

void tud_msc_capacity_cb(uint8_t lun, uint32_t *block_count, uint16_t *block_size) {
    (void)lun;
    *block_count = DISK_BLOCK_NUM;
    *block_size  = DISK_BLOCK_SIZE;
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
    if (lba >= DISK_BLOCK_NUM || offset > DISK_BLOCK_SIZE ||
        bufsize > DISK_BLOCK_SIZE - offset) return -1;

    const fj_slot_t *slot = fj_keys_get(fj_keys_active_slot());
    if (!slot) return -1;
    fj_led_activity();

    uint8_t sector[DISK_BLOCK_SIZE];
    memcpy(sector, msc_disk[lba], DISK_BLOCK_SIZE);

    /* Decrypt to clear text (only meaningful when unlocked). */
    uint8_t tweak[16];
    make_tweak(lba, tweak);
    if (!fj_xts_sector(slot->aes_key, tweak, sector, false)) return -1;

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
    if (lba >= DISK_BLOCK_NUM || offset > DISK_BLOCK_SIZE ||
        bufsize > DISK_BLOCK_SIZE - offset) return -1;

    const fj_slot_t *slot = fj_keys_get(fj_keys_active_slot());
    if (!slot) return -1;
    fj_led_activity();

    /* Rebuild the sector: decrypt, patch, re-encrypt. */
    uint8_t sector[DISK_BLOCK_SIZE];
    uint8_t tweak[16];
    make_tweak(lba, tweak);

    memcpy(sector, msc_disk[lba], DISK_BLOCK_SIZE);
    if (!fj_xts_sector(slot->aes_key, tweak, sector, false)) return -1;
    memcpy(sector + offset, buffer, bufsize);
    if (!fj_xts_sector(slot->aes_key, tweak, sector, true)) return -1;
    memcpy(msc_disk[lba], sector, DISK_BLOCK_SIZE);

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
    disk_ready = ready && fj_state_get() == FJ_STATE_UNLOCKED &&
                 fj_keys_get(fj_keys_active_slot()) != NULL;
}

#endif /* CFG_TUD_MSC */
