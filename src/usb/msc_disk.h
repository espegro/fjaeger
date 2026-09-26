/*
 * Fjaeger - encrypted MSC drive interface.
 */
#ifndef FJAEGER_MSC_DISK_H
#define FJAEGER_MSC_DISK_H

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Prepare the encrypted backing store. Call once at startup. */
void fj_msc_init(void);

/* Mount (true) or unmount (false) the volume to the host. */
void fj_msc_set_ready(bool ready);

#ifdef __cplusplus
}
#endif

#endif /* FJAEGER_MSC_DISK_H */