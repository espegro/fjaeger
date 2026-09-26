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

/* Lock/unmount the drive and discard the unwrapped disk key. */
void fj_msc_lock(void);

/* Mount (true) or unmount (false) the volume to the host. */
void fj_msc_set_ready(bool ready);

/* Whether the MSC volume is currently mounted/ready. */
bool fj_msc_is_ready(void);

/* Poll: flush any deferred flash writes. Call from the main loop. */
void fj_msc_task(void);

#ifdef __cplusplus
}
#endif

#endif /* FJAEGER_MSC_DISK_H */
