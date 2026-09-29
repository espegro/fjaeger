/*
 * Fjaeger - encrypted MSC drive interface.
 */
#ifndef FJAEGER_MSC_DISK_H
#define FJAEGER_MSC_DISK_H

#include <stdbool.h>
#include "state.h"   /* for fj_puk_result_t */

#ifdef __cplusplus
extern "C" {
#endif

#define FJ_MSC_BACKUP_MAX 4096u

/* Prepare the encrypted backing store. Call once at startup. */
void fj_msc_init(void);

/* Whether a disk PIN has been set (the drive can be unlocked). */
bool fj_msc_has_pin(void);

/* Whether the disk PIN is currently blocked (needs a PUK). */
bool fj_msc_pin_blocked(void);

/* Unlock/mount the drive by verifying the disk PIN. Returns true on success. */
bool fj_msc_unlock(const char *pin);

/* Clear a blocked disk-PIN counter with the recovery PUK. This deliberately
 * does not mount the disk: its key remains wrapped by the disk PIN, so the
 * correct disk PIN is still required afterwards. */
fj_puk_result_t fj_msc_unblock_puk(const char *puk);

/* Set or change the disk PIN. On first use it generates the drive's master
 * secret; changing it re-wraps the secret (no re-encryption of the drive).
 * Returns true on success. */
bool fj_msc_set_pin(const char *pin);

/* Explicitly rebuild the drive's filesystem + CRC table. Requires the device
 * to be unlocked and the disk key unwrapped (DISK SETPIN/UNLOCK). Destroys all
 * drive data; the console layer demands an explicit confirmation token. */
bool fj_msc_format(void);

/* Lock/unmount the drive and discard the unwrapped disk key. */
void fj_msc_lock(void);

/* Mount (true) or unmount (false) the volume to the host. */
void fj_msc_set_ready(bool ready);

/* Whether the MSC volume is currently mounted/ready. */
bool fj_msc_is_ready(void);

/* Poll: flush any deferred flash writes. Call from the main loop. */
void fj_msc_task(void);

/* Backup / restore a small encrypted blob as a FAT file ("FJAEGER.BAK").
 *
 * fj_msc_backup_write() creates/overwrites the file with 'len' bytes (must
 * be non-zero and <= FJ_MSC_BACKUP_MAX). fj_msc_backup_read() reads it back into 'out'
 * (capacity 'cap'); on success *len is set to the file size. Callers must
 * have flushed pending writes first; these functions flush internally.
 *
 * fj_msc_backup_delete() removes the file, frees its clusters and zeroes the
 * file's data sectors so the backup does not linger at rest. It is called
 * automatically when the drive is locked. Returns false if the drive is not
 * mounted. */
bool fj_msc_backup_write(const uint8_t *data, size_t len);
bool fj_msc_backup_read(uint8_t *out, size_t cap, size_t *len);
bool fj_msc_backup_delete(void);

/* Whether a backup file currently exists on the drive. */
bool fj_msc_backup_exists(void);

#ifdef __cplusplus
}
#endif

#endif /* FJAEGER_MSC_DISK_H */
