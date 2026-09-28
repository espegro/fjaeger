/*
 * Fjaeger - cooperative (non-blocking) secret operations.
 *
 * The long PBKDF2 derivations (SETPASS, UNLOCK, PUK, DISK, BACKUP, RESTORE)
 * run as cooperative jobs that are advanced a bounded amount of work per tick
 * from the firmware main loop. Between ticks the normal top-of-loop tud_task()
 * keeps USB alive, so the device no longer drops off the bus during a
 * multi-second derivation. Calling tud_task() from inside the KDF loop (the
 * previous approach) re-entered the TinyUSB device task and wedged the RP2350
 * USB controller, so it is deliberately avoided here.
 */
#ifndef FJAEGER_JOB_H
#define FJAEGER_JOB_H

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

#include "crypto.h"
#include "keys.h"

#ifdef __cplusplus
extern "C" {
#endif

#define FJ_SECRET_MAX 65          /* 64-char secret plus NUL */
#define FJ_BLOB_MAX   4096        /* backup/restore blob buffer */
#define FJ_JOB_KDF_CHUNK 512u     /* PBKDF2 inner iterations per tick */

/* Result of a completed job. */
typedef enum {
    FJ_RES_OK = 0,
    FJ_RES_ERR,          /* generic failure */
    FJ_RES_BAD_SECRET,   /* short/invalid secret, or device locked */
    FJ_RES_BAD_PIN,      /* wrong passphrase / PIN */
    FJ_RES_BLOCKED,      /* brute-force blocked */
    FJ_RES_WRONG_PUK,
    FJ_RES_NO_PUK,
    FJ_RES_WIPED,        /* too many wrong PUKs -> factory wipe */
    FJ_RES_DRIVE,        /* storage not ready / I/O failure */
} fj_job_result_t;

typedef enum {
    FJ_JOB_NONE = 0,
    /* state-layer jobs (state.c) */
    FJ_JOB_SETPASS,
    FJ_JOB_UNLOCK,
    FJ_JOB_SETPUK,
    FJ_JOB_UNLOCKPUK,
    FJ_JOB_VERIFY_PUK,
    FJ_JOB_BACKUP,
    FJ_JOB_RESTORE,
    /* disk-layer jobs (msc_disk.c) */
    FJ_JOB_DISK_SETPIN,
    FJ_JOB_DISK_UNLOCK,
    FJ_JOB_DISK_UNBLOCK,
} fj_job_kind_t;

/* State-layer job. Owned and stepped by state.c. The console keeps one of
 * these as a static; synchronous wrappers reuse a static too. */
typedef struct {
    fj_job_kind_t kind;
    uint8_t phase;
    fj_job_result_t result;
    bool busy;

    char a1[FJ_SECRET_MAX], a2[FJ_SECRET_MAX], a3[FJ_SECRET_MAX];

    fj_kdf_t kdf[5];          /* up to five sequential derivations */
    uint8_t salt[5][16];
    uint8_t out[5][32];
    uint8_t enc[5][32];
    uint8_t nonce[5][12];
    uint8_t tag[5][16];
    uint8_t blob[FJ_BLOB_MAX];
    size_t  blob_len;
    fj_backup_payload_t payload;
} fj_state_job_t;

/* Disk-layer job. Owned and stepped by msc_disk.c. */
typedef struct {
    fj_job_kind_t kind;
    uint8_t phase;
    fj_job_result_t result;
    bool busy;

    char a1[FJ_SECRET_MAX];

    fj_kdf_t kdf[2];
    uint8_t salt[2][16];
    uint8_t enc[32];
    uint8_t nonce[12];
    uint8_t tag[16];
    bool first_time;          /* DISK SETPIN first set vs re-key */

    fj_state_job_t puk;       /* embedded PUK verification (DISK UNBLOCK) */
} fj_disk_job_t;

/* state.c: start/step a state-layer job. step() returns true while the job
 * is still running and false once finished (busy cleared, result valid). */
void fj_state_job_start(fj_state_job_t *j, fj_job_kind_t kind,
                        const char *a1, const char *a2, const char *a3);
bool fj_state_job_step(fj_state_job_t *j);

/* msc_disk.c: start/step a disk-layer job. */
void fj_disk_job_start(fj_disk_job_t *j, fj_job_kind_t kind, const char *a1);
bool fj_disk_job_step(fj_disk_job_t *j);

#ifdef __cplusplus
}
#endif

#endif /* FJAEGER_JOB_H */
