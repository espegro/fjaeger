/*
 * Fjaeger - encrypted MSC drive interface.
 */
#ifndef FJAEGER_MSC_DISK_H
#define FJAEGER_MSC_DISK_H

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Prepare the encrypted backing store. Call once at startup. Ensures a
 * permanent disk key exists and (re)initialises the flash partition on
 * first use. */
void fj_msc_init(void);

/* Mount (true) or unmount (false) the volume to the host. */
void fj_msc_set_ready(bool ready);

/* Poll: flush any deferred flash writes. Call from the main loop. */
void fj_msc_task(void);

#ifdef __cplusplus
}
#endif

#endif /* FJAEGER_MSC_DISK_H */