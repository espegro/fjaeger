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

#define DISK_TOTAL_BLOCKS      (DISK_FLASH_SIZE / DISK_BLOCK_SIZE)   /* 3072 */

/* A persistent CRC-32 table protects every 4 KiB data block against
 * corruption from power loss or tampering. The table is stored in clear
 * text in the last few blocks of the partition. */
#define CRC_TABLE_BLOCKS       4
#define CRCS_PER_BLOCK         (DISK_BLOCK_SIZE / 4)                 /* 1024 */
#define DISK_DATA_BLOCKS       (DISK_TOTAL_BLOCKS - CRC_TABLE_BLOCKS) /* 3068 */
#define DISK_TOTAL_SECTORS     (DISK_DATA_BLOCKS * DISK_SECTORS_PER_BLOCK) /* 24544 */
#define DISK_TABLE_START_BLOCK DISK_DATA_BLOCKS

/* FAT16 geometry (computed at init). */
static uint16_t fat_sectors;
static uint32_t root_dir_lba;    /* first root-directory sector */
static uint32_t data_lba;        /* first data-cluster sector */
static uint32_t total_clusters;

static bool disk_ready = false;
static bool fs_initialised = false;
static bool disk_unlocked = false;   /* set once the disk PIN is verified */

/* Permanent disk key (two AES-128 keys for XTS). */
static uint8_t disk_key[FJ_AES_KEY_BYTES];

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

/* Forward declarations (defined further below). */
static bool read_block_apply(uint32_t idx, uint8_t clear[DISK_BLOCK_SIZE]);
static void write_block(uint32_t idx, const uint8_t clear[DISK_BLOCK_SIZE]);

/* ------------------------------------------------------------------ */
/* Integrity: a persistent CRC-32 per 4 KiB data block.               */
/* The table lives in clear text in the last CRC_TABLE_BLOCKS blocks   */
/* of the partition. A magic + count header marks a valid table.       */
/* ------------------------------------------------------------------ */
#define CRC_MAGIC 0x464A4352u /* "FJCR" */
#define CRC_HEADER_SIZE 8      /* magic + count, before the CRC entries */

static uint32_t block_crcs[DISK_DATA_BLOCKS];
static bool crc_dirty = false;

static uint32_t crc32_update(uint32_t crc, const uint8_t *data, size_t len) {
    while (len--) {
        crc ^= *data++;
        for (unsigned bit = 0; bit < 8; bit++)
            crc = (crc >> 1) ^ (0xedb88320u & (uint32_t)-(int32_t)(crc & 1));
    }
    return crc;
}

static uint32_t crc32_block(const uint8_t data[DISK_BLOCK_SIZE]) {
    return crc32_update(0xffffffffu, data, DISK_BLOCK_SIZE) ^ 0xffffffffu;
}

/* Read a raw (clear-text) flash block without XTS. */
static void read_raw_block(uint32_t idx, uint8_t out[DISK_BLOCK_SIZE]) {
    memcpy(out, (const void *)(XIP_BASE + DISK_FLASH_START + idx * DISK_BLOCK_SIZE),
           DISK_BLOCK_SIZE);
}

/* Write a raw (clear-text) flash block without XTS. */
static void write_raw_block(uint32_t idx, const uint8_t data[DISK_BLOCK_SIZE]) {
    uint32_t offset = DISK_FLASH_START + idx * DISK_BLOCK_SIZE;
    uint32_t ints = save_and_disable_interrupts();
    flash_range_erase(offset, DISK_BLOCK_SIZE);
    flash_range_program(offset, data, DISK_BLOCK_SIZE);
    restore_interrupts(ints);
}

/* Persist the in-RAM CRC table to the reserved flash blocks. */
static void crc_table_write(void) {
    for (uint32_t tb = 0; tb < CRC_TABLE_BLOCKS; tb++) {
        uint8_t buf[DISK_BLOCK_SIZE];
        memset(buf, 0xff, sizeof(buf));
        for (uint32_t i = 0; i < DISK_DATA_BLOCKS; i++) {
            uint32_t g = CRC_HEADER_SIZE + i * 4;
            if (g / DISK_BLOCK_SIZE == tb)
                memcpy(buf + (g % DISK_BLOCK_SIZE), &block_crcs[i], 4);
        }
        if (tb == 0) {
            uint32_t magic = CRC_MAGIC, count = DISK_DATA_BLOCKS;
            memcpy(buf, &magic, 4);
            memcpy(buf + 4, &count, 4);
        }
        write_raw_block(DISK_TABLE_START_BLOCK + tb, buf);
    }
    crc_dirty = false;
}

/* Load the CRC table from flash. Returns true if a valid table was found. */
static bool crc_table_load(void) {
    uint8_t buf[DISK_BLOCK_SIZE];
    uint32_t cur_tb = 0;
    read_raw_block(DISK_TABLE_START_BLOCK, buf);
    uint32_t magic, count;
    memcpy(&magic, buf, 4);
    memcpy(&count, buf + 4, 4);
    if (magic != CRC_MAGIC || count != DISK_DATA_BLOCKS) return false;
    for (uint32_t i = 0; i < DISK_DATA_BLOCKS; i++) {
        uint32_t g = CRC_HEADER_SIZE + i * 4;
        uint32_t tb = g / DISK_BLOCK_SIZE;
        if (tb != cur_tb) {
            read_raw_block(DISK_TABLE_START_BLOCK + tb, buf);
            cur_tb = tb;
        }
        memcpy(&block_crcs[i], buf + (g % DISK_BLOCK_SIZE), 4);
    }
    crc_dirty = false;
    return true;
}

/* Build the CRC table by reading every data block from flash. */
static void crc_table_build_from_disk(void) {
    for (uint32_t i = 0; i < DISK_DATA_BLOCKS; i++) {
        uint8_t clear[DISK_BLOCK_SIZE];
        if (read_block_apply(i, clear)) {
            block_crcs[i] = crc32_block(clear);
        } else {
            block_crcs[i] = 0;
        }
    }
    crc_dirty = true;
}

/* ------------------------------------------------------------------ */
/* Deferred write-behind queue.                                       */
/*                                                                     */
/* USB MSC callbacks only queue sector writes and never touch flash    */
/* directly. fj_msc_task() (main loop) performs the actual flash       */
/* erase/program, so long interrupt-disabled operations never happen   */
/* inside a USB transaction.                                           */
/* ------------------------------------------------------------------ */
#define WRITE_QUEUE_SIZE 64

typedef struct {
    uint32_t lba;
    uint8_t data[DISK_SECTOR_SIZE];
    bool in_use;
} pending_write_t;

static pending_write_t wq[WRITE_QUEUE_SIZE];

static bool wq_enqueue(uint32_t lba, const uint8_t data[DISK_SECTOR_SIZE]) {
    for (unsigned i = 0; i < WRITE_QUEUE_SIZE; i++) {
        if (!wq[i].in_use) {
            wq[i].lba = lba;
            memcpy(wq[i].data, data, DISK_SECTOR_SIZE);
            wq[i].in_use = true;
            return true;
        }
    }
    return false; /* queue full */
}

static bool wq_empty(void) {
    for (unsigned i = 0; i < WRITE_QUEUE_SIZE; i++) {
        if (wq[i].in_use) return false;
    }
    return true;
}

static void wq_reset(void) {
    for (unsigned i = 0; i < WRITE_QUEUE_SIZE; i++) wq[i].in_use = false;
}

/* Apply any pending writes that belong to flash block 'idx' onto the
 * decrypted block 'clear' (8 sectors in clear text). */
static void wq_apply_to_block(uint32_t idx, uint8_t clear[DISK_BLOCK_SIZE]) {
    for (unsigned i = 0; i < WRITE_QUEUE_SIZE; i++) {
        if (!wq[i].in_use) continue;
        if (block_index_for_lba(wq[i].lba) != idx) continue;
        uint32_t off = (wq[i].lba % DISK_SECTORS_PER_BLOCK) * DISK_SECTOR_SIZE;
        memcpy(clear + off, wq[i].data, DISK_SECTOR_SIZE);
    }
}

/* Read flash block 'idx' from XIP, decrypt all 8 sectors and apply any
 * pending writes for that block. Result is 4 KiB of clear text. */
static bool read_block_apply(uint32_t idx, uint8_t clear[DISK_BLOCK_SIZE]) {
    const uint8_t *raw = (const uint8_t *)(XIP_BASE + DISK_FLASH_START +
                                           idx * DISK_BLOCK_SIZE);
    for (uint32_t s = 0; s < DISK_SECTORS_PER_BLOCK; s++) {
        uint32_t lba = idx * DISK_SECTORS_PER_BLOCK + s;
        uint8_t tweak[16];
        make_tweak(lba, tweak);
        memcpy(clear + s * DISK_SECTOR_SIZE, raw + s * DISK_SECTOR_SIZE,
               DISK_SECTOR_SIZE);
        if (!fj_xts_sector(disk_key, tweak, clear + s * DISK_SECTOR_SIZE, false))
            return false;
    }
    wq_apply_to_block(idx, clear);
    return true;
}

/* Encrypt and write one 4 KiB block from clear text, updating its CRC. */
static void write_block(uint32_t idx, const uint8_t clear[DISK_BLOCK_SIZE]) {
    uint8_t enc[DISK_BLOCK_SIZE];
    for (uint32_t s = 0; s < DISK_SECTORS_PER_BLOCK; s++) {
        uint32_t lba = idx * DISK_SECTORS_PER_BLOCK + s;
        uint8_t tweak[16];
        make_tweak(lba, tweak);
        memcpy(enc + s * DISK_SECTOR_SIZE, clear + s * DISK_SECTOR_SIZE,
               DISK_SECTOR_SIZE);
        if (!fj_xts_sector(disk_key, tweak, enc + s * DISK_SECTOR_SIZE, true)) {
            return; /* failed to encrypt; leave on-flash copy intact */
        }
    }
    uint32_t offset = DISK_FLASH_START + idx * DISK_BLOCK_SIZE;
    uint32_t ints = save_and_disable_interrupts();
    flash_range_erase(offset, DISK_BLOCK_SIZE);
    flash_range_program(offset, enc, DISK_BLOCK_SIZE);
    restore_interrupts(ints);
    block_crcs[idx] = crc32_block(clear);
    crc_dirty = true;
}

/* Write all pending sectors to flash. Each touched 4 KiB block is written
 * once (reads current on-flash block, applies pending writes, encrypts),
 * then the CRC table is persisted if any block changed. */
static void flush_pending_writes(void) {
    if (wq_empty() && !crc_dirty) return;
    for (unsigned i = 0; i < WRITE_QUEUE_SIZE; i++) {
        if (!wq[i].in_use) continue;
        uint32_t idx = block_index_for_lba(wq[i].lba);
        uint8_t clear[DISK_BLOCK_SIZE];
        if (read_block_apply(idx, clear)) {
            write_block(idx, clear);
        }
        /* Drop every queued write belonging to this block. */
        for (unsigned j = 0; j < WRITE_QUEUE_SIZE; j++) {
            if (wq[j].in_use && block_index_for_lba(wq[j].lba) == idx)
                wq[j].in_use = false;
        }
    }
    if (crc_dirty) crc_table_write();
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
 * fast instead of erasing the whole 12 MiB. Also builds and writes the
 * integrity CRC table. */
static void init_filesystem(void) {
    uint32_t metadata_end_block = (data_lba + DISK_SECTORS_PER_BLOCK - 1) /
                                  DISK_SECTORS_PER_BLOCK;
    if (metadata_end_block > DISK_DATA_BLOCKS)
        metadata_end_block = DISK_DATA_BLOCKS;

    for (uint32_t idx = 0; idx < metadata_end_block; idx++) {
        uint8_t clear[DISK_BLOCK_SIZE];
        for (uint32_t s = 0; s < DISK_SECTORS_PER_BLOCK; s++) {
            uint32_t lba = idx * DISK_SECTORS_PER_BLOCK + s;
            if (lba >= DISK_TOTAL_SECTORS) break;
            build_clear_sector(lba, clear + s * DISK_SECTOR_SIZE);
        }
        write_block(idx, clear);
    }
    /* Build CRC for every data block (metadata above + erased data). */
    crc_table_build_from_disk();
    crc_table_write();
    wq_reset();
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

/* Decrypt the boot sector, check its 0x55 0xAA signature AND its CRC from
 * the persistent integrity table. */
static bool boot_sector_valid(void) {
    uint8_t clear[DISK_BLOCK_SIZE];
    if (!read_block_apply(0, clear)) return false;
    if (!(clear[510] == 0x55 && clear[511] == 0xAA)) return false;
    return crc32_block(clear) == block_crcs[0];
}

/* ------------------------------------------------------------------ */
/* Backup file: minimal FAT16 file operations for "FJAEGER.BAK".       */
/* ------------------------------------------------------------------ */
#define BACKUP_NAME        "FJAEGER"      /* 8.3 name (padded to 8) */
#define BACKUP_EXT         "BAK"
#define BACKUP_ATTR        0x20           /* archive */
#define FAT_EOC            0xFFFF
#define FAT_FREE           0x0000
#define ROOT_ENTRY_SIZE    32
#define ROOT_ENTRIES       (32 * DISK_SECTOR_SIZE / ROOT_ENTRY_SIZE) /* 512 */
#define MAX_BACKUP_SIZE    4096

static bool read_sector_raw(uint32_t lba, uint8_t out[DISK_SECTOR_SIZE]) {
    uint8_t clear[DISK_BLOCK_SIZE];
    if (!read_block_apply(block_index_for_lba(lba), clear)) return false;
    memcpy(out, clear + (lba % DISK_SECTORS_PER_BLOCK) * DISK_SECTOR_SIZE,
           DISK_SECTOR_SIZE);
    return true;
}

/* Read-modify-write one clear-text sector via the block layer. */
static void write_sector_raw(uint32_t lba, const uint8_t in[DISK_SECTOR_SIZE]) {
    uint8_t clear[DISK_BLOCK_SIZE];
    read_block_apply(block_index_for_lba(lba), clear);
    memcpy(clear + (lba % DISK_SECTORS_PER_BLOCK) * DISK_SECTOR_SIZE,
           in, DISK_SECTOR_SIZE);
    write_block(block_index_for_lba(lba), clear);
}

/* FAT 1 begins at reserved sector (LBA 1). Entry 'e' is at byte 2*e. */
static uint32_t fat1_lba(uint32_t byte_off) {
    return 1u + byte_off / DISK_SECTOR_SIZE;
}

static bool fat_read_entry(uint32_t e, uint16_t *val) {
    uint8_t sec[DISK_SECTOR_SIZE];
    if (!read_sector_raw(fat1_lba(e * 2), sec)) return false;
    uint32_t off = (e * 2) % DISK_SECTOR_SIZE;
    *val = (uint16_t)(sec[off] | ((uint16_t)sec[off + 1] << 8));
    return true;
}

/* Write 'val' to FAT entry 'e' in both FAT copies (mirrored). */
static void fat_write_entry(uint32_t e, uint16_t val) {
    uint32_t off = (e * 2) % DISK_SECTOR_SIZE;
    uint8_t sec[DISK_SECTOR_SIZE];
    read_sector_raw(fat1_lba(e * 2), sec);
    sec[off] = val & 0xff;
    sec[off + 1] = (uint8_t)((val >> 8) & 0xff);
    write_sector_raw(fat1_lba(e * 2), sec);
    /* FAT 2 mirror starts after FAT 1. */
    read_sector_raw(1u + fat_sectors + (e * 2) / DISK_SECTOR_SIZE, sec);
    sec[(e * 2) % DISK_SECTOR_SIZE] = val & 0xff;
    sec[((e * 2) % DISK_SECTOR_SIZE) + 1] = (uint8_t)((val >> 8) & 0xff);
    write_sector_raw(1u + fat_sectors + (e * 2) / DISK_SECTOR_SIZE, sec);
}

/* Cluster number -> data LBA (FAT16: cluster 2 starts the data region). */
static uint32_t cluster_lba(uint32_t cluster) {
    return data_lba + (cluster - 2);
}

/* Find a contiguous run of 'n' free clusters starting at or after 'start'.
 * Returns the first cluster, or 0 if none. */
static uint32_t find_free_run(uint32_t n, uint32_t start) {
    uint32_t run = 0;
    uint32_t first = 0;
    for (uint32_t c = start; c <= total_clusters + 1; c++) {
        uint16_t v;
        if (!fat_read_entry(c, &v)) return 0;
        if (v == FAT_FREE) {
            if (run == 0) first = c;
            run++;
            if (run >= n) return first;
        } else {
            run = 0;
        }
    }
    return 0;
}

/* Locate the root-directory entry named FJAEGER.BAK. Returns its byte offset
 * into the root directory, or -1 if not present. */
static int find_backup_root_entry(void) {
    uint8_t name[8], ext[3];
    memset(name, ' ', 8);
    memcpy(name, BACKUP_NAME, strlen(BACKUP_NAME));
    memset(ext, ' ', 3);
    memcpy(ext, BACKUP_EXT, strlen(BACKUP_EXT));

    for (uint32_t r = 0; r < ROOT_ENTRIES; r++) {
        uint32_t byte_off = r * ROOT_ENTRY_SIZE;
        uint32_t lba = root_dir_lba + byte_off / DISK_SECTOR_SIZE;
        uint8_t sec[DISK_SECTOR_SIZE];
        if (!read_sector_raw(lba, sec)) return -1;
        const uint8_t *e = sec + (byte_off % DISK_SECTOR_SIZE);
        if (e[0] == 0x00) return -1;        /* end of directory */
        if (e[0] == 0xE5) continue;         /* free entry */
        if ((e[11] & 0x08) != 0) continue;  /* skip volume label */
        if (memcmp(e, name, 8) == 0 && memcmp(e + 8, ext, 3) == 0)
            return (int)byte_off;
    }
    return -1;
}

static void write_root_entry(uint32_t byte_off, const uint8_t entry[ROOT_ENTRY_SIZE]) {
    uint32_t lba = root_dir_lba + byte_off / DISK_SECTOR_SIZE;
    uint8_t sec[DISK_SECTOR_SIZE];
    read_sector_raw(lba, sec);
    memcpy(sec + (byte_off % DISK_SECTOR_SIZE), entry, ROOT_ENTRY_SIZE);
    write_sector_raw(lba, sec);
}

bool fj_msc_backup_exists(void) {
    if (!disk_ready || !fs_initialised) return false;
    return find_backup_root_entry() >= 0;
}

bool fj_msc_backup_write(const uint8_t *data, size_t len) {
    if (!disk_ready || !fs_initialised) return false;
    if (!data || len == 0 || len > MAX_BACKUP_SIZE) return false;
    flush_pending_writes();

    uint32_t clusters = (uint32_t)((len + DISK_SECTOR_SIZE - 1) / DISK_SECTOR_SIZE);
    uint32_t first = find_free_run(clusters, 2);
    if (first == 0) return false;

    uint8_t name[8], ext[3];
    memset(name, ' ', 8);
    memcpy(name, BACKUP_NAME, strlen(BACKUP_NAME));
    memset(ext, ' ', 3);
    memcpy(ext, BACKUP_EXT, strlen(BACKUP_EXT));

    /* Write data clusters. */
    size_t pos = 0;
    uint32_t c = first;
    for (uint32_t i = 0; i < clusters; i++, c++) {
        uint8_t sec[DISK_SECTOR_SIZE];
        memset(sec, 0, sizeof(sec));
        size_t n = len - pos;
        if (n > DISK_SECTOR_SIZE) n = DISK_SECTOR_SIZE;
        memcpy(sec, data + pos, n);
        pos += n;
        write_sector_raw(cluster_lba(c), sec);
    }

    /* Link the chain in the FAT (last cluster -> EOC). */
    for (uint32_t i = 0; i < clusters; i++) {
        uint16_t next = (i + 1 < clusters) ? (uint16_t)(first + i + 1) : FAT_EOC;
        fat_write_entry(first + i, next);
    }

    /* Root directory entry. */
    uint8_t entry[ROOT_ENTRY_SIZE];
    memset(entry, 0, sizeof(entry));
    memcpy(entry, name, 8);
    memcpy(entry + 8, ext, 3);
    entry[11] = BACKUP_ATTR;
    /* DOS time/date: fixed, not important. */
    entry[20] = 0x00; entry[21] = 0x00;   /* hi start cluster */
    entry[26] = (uint8_t)(first & 0xff);
    entry[27] = (uint8_t)((first >> 8) & 0xff);
    entry[28] = (uint8_t)(len & 0xff);
    entry[29] = (uint8_t)((len >> 8) & 0xff);
    entry[30] = (uint8_t)((len >> 16) & 0xff);
    entry[31] = (uint8_t)((len >> 24) & 0xff);

    /* Find a free root slot (reuse existing FJAEGER.BAK slot if any, else
     * the first free slot). */
    int slot = find_backup_root_entry();
    if (slot < 0) {
        /* scan for a free (0xE5) or end-of-dir (0x00) slot */
        for (uint32_t r = 0; r < ROOT_ENTRIES; r++) {
            uint32_t bo = r * ROOT_ENTRY_SIZE;
            uint8_t sec[DISK_SECTOR_SIZE];
            if (!read_sector_raw(root_dir_lba + bo / DISK_SECTOR_SIZE, sec)) return false;
            const uint8_t *e = sec + (bo % DISK_SECTOR_SIZE);
            if (e[0] == 0x00 || e[0] == 0xE5) { slot = (int)bo; break; }
        }
    }
    if (slot < 0) return false;   /* directory full */
    write_root_entry((uint32_t)slot, entry);

    flush_pending_writes();
    return true;
}

bool fj_msc_backup_read(uint8_t *out, size_t cap, size_t *len) {
    if (!disk_ready || !fs_initialised) return false;
    if (!out || !len) return false;
    flush_pending_writes();

    int slot = find_backup_root_entry();
    if (slot < 0) return false;

    uint8_t sec[DISK_SECTOR_SIZE];
    uint32_t bo = (uint32_t)slot;
    if (!read_sector_raw(root_dir_lba + bo / DISK_SECTOR_SIZE, sec)) return false;
    const uint8_t *e = sec + (bo % DISK_SECTOR_SIZE);
    uint32_t size = (uint32_t)e[28] | ((uint32_t)e[29] << 8) |
                    ((uint32_t)e[30] << 16) | ((uint32_t)e[31] << 24);
    uint32_t first = (uint32_t)e[26] | ((uint32_t)e[27] << 8);
    if (first < 2 || size == 0 || size > MAX_BACKUP_SIZE) return false;
    if (cap < size) return false;

    uint32_t clusters = (size + DISK_SECTOR_SIZE - 1) / DISK_SECTOR_SIZE;
    uint32_t c = first;
    size_t pos = 0;
    for (uint32_t i = 0; i < clusters && c >= 2; i++) {
        if (!read_sector_raw(cluster_lba(c), sec)) return false;
        size_t n = size - pos;
        if (n > DISK_SECTOR_SIZE) n = DISK_SECTOR_SIZE;
        memcpy(out + pos, sec, n);
        pos += n;
        uint16_t next;
        if (!fat_read_entry(c, &next)) return false;
        c = next;
        if (next == FAT_EOC) break;
    }
    if (pos != size) return false;
    *len = size;
    return true;
}

bool fj_msc_backup_delete(void) {
    if (!disk_ready || !fs_initialised) return false;
    flush_pending_writes();

    int slot = find_backup_root_entry();
    if (slot < 0) return true;   /* nothing to delete */

    /* Read file metadata to free its clusters. */
    uint8_t sec[DISK_SECTOR_SIZE];
    uint32_t bo = (uint32_t)slot;
    if (!read_sector_raw(root_dir_lba + bo / DISK_SECTOR_SIZE, sec)) return false;
    const uint8_t *e = sec + (bo % DISK_SECTOR_SIZE);
    uint32_t first = (uint32_t)e[26] | ((uint32_t)e[27] << 8);

    /* Zero the data sectors, free the FAT chain. */
    uint32_t c = first;
    uint32_t guard = 0;
    while (c >= 2 && c <= total_clusters + 1 && guard++ < 32) {
        uint16_t next;
        if (!fat_read_entry(c, &next)) break;
        uint8_t zero[DISK_SECTOR_SIZE];
        memset(zero, 0, sizeof(zero));
        write_sector_raw(cluster_lba(c), zero);
        fat_write_entry(c, FAT_FREE);
        if (next == FAT_EOC) break;
        c = next;
    }

    /* Mark the root entry free. */
    sec[(bo % DISK_SECTOR_SIZE)] = 0xE5;
    write_sector_raw(root_dir_lba + bo / DISK_SECTOR_SIZE, sec);

    flush_pending_writes();
    return true;
}

/* ------------------------------------------------------------------ */
/* Public API                                                          */
/* ------------------------------------------------------------------ */
void fj_msc_init(void) {
    compute_geometry();
    wq_reset();
    disk_ready = false;
    disk_unlocked = false;
    fs_initialised = false;
}

/* Derive the 32-byte disk wrap/verification key from the disk PIN and salt
 * using slow, salted PBKDF2-HMAC-SHA256. The same value is used both to wrap
 * the disk key and to verify the PIN, so a dumped store cannot be brute-forced
 * offline with a fast hash. */
static bool disk_derive(const char *pin, const uint8_t salt[16], uint8_t out[32]) {
    return fj_pbkdf2_sha256((const uint8_t *)pin, strlen(pin), salt, 16,
                            FJ_PBKDF2_ITERATIONS, out);
}

/* Verify the disk PIN (constant-time) and unwrap the disk key into disk_key. */
static bool disk_unwrap(const char *pin) {
    uint8_t enc[32], salt[16], hash[32];
    fj_keys_get_disk_secret(enc, salt, hash);

    uint8_t w[32];
    if (!disk_derive(pin, salt, w)) return false;

    uint8_t acc = 0;
    for (int i = 0; i < 32; i++) acc |= w[i] ^ hash[i];
    if (acc != 0) return false;

    for (int i = 0; i < 32; i++) disk_key[i] = enc[i] ^ w[i];
    return true;
}

/* Build or verify the filesystem using the live (unwrapped) disk key. */
static bool fj_msc_prepare(void) {
    if (!crc_table_load()) {
        init_filesystem();
    } else if (!boot_sector_valid()) {
        init_filesystem();
    }
    fs_initialised = true;
    return true;
}

bool fj_msc_has_pin(void) {
    return fj_keys_disk_secret_set();
}

/* Whether the disk PIN is currently blocked (needs a PUK). */
bool fj_msc_pin_blocked(void) {
    fj_security_t sec;
    return fj_keys_get_security(&sec) && sec.disk_blocked;
}

bool fj_msc_unlock(const char *pin) {
    if (!pin || !fj_keys_disk_secret_set()) return false;

    /* Brute-force protection: a blocked disk PIN requires the PUK, and a
     * growing delay is imposed between failed attempts. */
    fj_security_t sec;
    if (!fj_keys_get_security(&sec)) return false;
    if (sec.disk_blocked) return false;
    if (!fj_state_brute_ok(FJ_BRUTE_DISK)) return false;

    if (!disk_unwrap(pin)) {
        /* Wrong disk PIN: count it, grow the backoff delay and block once
         * the limit is reached. */
        sec.disk_fail++;
        if (sec.disk_fail >= FJ_MAX_PIN_FAILS) sec.disk_blocked = 1;
        fj_keys_set_security(&sec);
        fj_state_brute_failure(FJ_BRUTE_DISK);
        return false;
    }

    /* Correct disk PIN resets the counter and the backoff delay. */
    if (sec.disk_fail != 0 || sec.disk_blocked) {
        sec.disk_fail = 0;
        sec.disk_blocked = 0;
        fj_keys_set_security(&sec);
    }
    fj_state_brute_success(FJ_BRUTE_DISK);

    if (!fj_msc_prepare()) return false;
    disk_unlocked = true;
    disk_ready = true;
    return true;
}

/* The disk key is wrapped only by the disk PIN. A PUK can safely clear the
 * brute-force block, but cannot substitute for that PIN without weakening
 * the at-rest encryption model. */
fj_puk_result_t fj_msc_unblock_puk(const char *puk) {
    fj_puk_result_t result = fj_state_verify_puk(puk);
    if (result != FJ_PUK_OK) return result;

    fj_security_t sec;
    if (!fj_keys_get_security(&sec)) return FJ_PUK_WRONG;
    sec.disk_fail = 0;
    sec.disk_blocked = 0;
    return fj_keys_set_security(&sec) ? FJ_PUK_OK : FJ_PUK_WRONG;
}

void fj_msc_lock(void) {
    if (disk_ready) {
        /* Remove any backup file so it does not linger on the (still
         * encrypted) disk once the drive is locked. */
        fj_msc_backup_delete();
        flush_pending_writes();
    }
    disk_ready = false;
    disk_unlocked = false;
    memset(disk_key, 0, sizeof(disk_key));
}

bool fj_msc_set_pin(const char *pin) {
    size_t n = pin ? strlen(pin) : 0;
    if (n < 4 || n > 32) return false;

    uint8_t salt[16], enc[32], wrap[32], hash[32];
    if (!fj_keys_disk_secret_set()) {
        /* First-time: generate a fresh master secret for the drive. */
        fj_random(salt, sizeof(salt));
        fj_random(disk_key, sizeof(disk_key));
    } else {
        /* Change PIN: require the drive to be unlocked (holds the secret). */
        if (!disk_unlocked) return false;
        fj_random(salt, sizeof(salt));
    }

    if (!disk_derive(pin, salt, wrap)) return false;
    for (int i = 0; i < 32; i++) enc[i] = disk_key[i] ^ wrap[i];
    memcpy(hash, wrap, 32);   /* verification hash == wrap key (same PBKDF2) */

    if (!fj_keys_set_disk_secret(enc, salt, hash)) return false;
    if (!fj_msc_prepare()) return false;
    disk_unlocked = true;
    disk_ready = true;
    return true;
}

void fj_msc_task(void) {
    if (disk_ready) flush_pending_writes();
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
    if (!disk_ready || !fs_initialised) {
        /* Report "media not present" until the drive is explicitly unlocked. */
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
    if (!disk_ready) return -1;
    if (lba >= DISK_TOTAL_SECTORS || offset > DISK_SECTOR_SIZE ||
        bufsize > DISK_SECTOR_SIZE - offset) return -1;

    fj_led_activity();
    uint8_t clear[DISK_BLOCK_SIZE];
    if (!read_block_apply(block_index_for_lba(lba), clear)) return -1;
    uint32_t off = (lba % DISK_SECTORS_PER_BLOCK) * DISK_SECTOR_SIZE;
    memcpy(buffer, clear + off + offset, bufsize);
    return (int32_t)bufsize;
}

bool tud_msc_is_writable_cb(uint8_t lun) {
    (void)lun;
    /* Writes only allowed while the drive is unlocked. */
    return disk_ready;
}

int32_t tud_msc_write10_cb(uint8_t lun, uint32_t lba, uint32_t offset,
                           uint8_t *buffer, uint32_t bufsize) {
    (void)lun;
    if (!disk_ready) return -1;
    if (lba >= DISK_TOTAL_SECTORS || offset > DISK_SECTOR_SIZE ||
        bufsize > DISK_SECTOR_SIZE - offset) return -1;

    fj_led_activity();
    uint8_t sector[DISK_SECTOR_SIZE];
    if (offset == 0 && bufsize == DISK_SECTOR_SIZE) {
        /* Full-sector write: enqueue directly. */
        memcpy(sector, buffer, DISK_SECTOR_SIZE);
    } else {
        /* Partial write: read the existing sector, patch, enqueue full sector. */
        uint8_t clear[DISK_BLOCK_SIZE];
        if (!read_block_apply(block_index_for_lba(lba), clear)) return -1;
        uint32_t off = (lba % DISK_SECTORS_PER_BLOCK) * DISK_SECTOR_SIZE;
        memcpy(sector, clear + off, DISK_SECTOR_SIZE);
        memcpy(sector + offset, buffer, bufsize);
    }

    if (!wq_enqueue(lba, sector)) {
        /* Queue full (should be rare because the main loop flushes). Fall
         * back to flushing now to guarantee the write is not lost. */
        flush_pending_writes();
        if (!wq_enqueue(lba, sector)) return -1;
    }
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

/* Set ready only when the drive has been unlocked with its PIN. */
void fj_msc_set_ready(bool ready) {
    /* On unmount/lock, flush any pending writes to flash first so no data
     * is lost and the decrypted volume is never left exposed. */
    if (!ready) flush_pending_writes();
    disk_ready = ready && disk_unlocked && fs_initialised;
}

bool fj_msc_is_ready(void) {
    return disk_ready && disk_unlocked && fs_initialised;
}

#endif /* CFG_TUD_MSC */
