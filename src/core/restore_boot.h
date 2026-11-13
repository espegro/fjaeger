#ifndef FJ_RESTORE_BOOT_H
#define FJ_RESTORE_BOOT_H
#include <stdbool.h>
/* Called after crypto self-test and before key initialization or USB startup.
 * Failure prohibits normal service; never infer CLEAN from corrupt journal. */
bool fj_restore_boot_recover(void);
#endif
