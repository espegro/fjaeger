#ifndef FJ_RESTORE_INTERNAL_H
#define FJ_RESTORE_INTERNAL_H
#include "restore_coordinator.h"
/* Recovery callbacks shared by boot and an authorized restore operation. */
fj_restore_ops_t fj_restore_store_ops(void);
#endif
