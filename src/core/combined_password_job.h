#ifndef FJ_COMBINED_PASSWORD_JOB_H
#define FJ_COMBINED_PASSWORD_JOB_H
#include "combined_backup.h"
#include "crypto.h"

#define FJ_COMBINED_PASSWORD_HEADER 24u
#define FJ_COMBINED_PASSWORD_SIZE (FJ_COMBINED_PASSWORD_HEADER + FJ_COMBINED_BACKUP_SIZE)
#define FJ_COMBINED_KDF_STEPS_PER_TICK 512u

typedef enum {
    FJ_COMBINED_JOB_IDLE, FJ_COMBINED_JOB_RUNNING,
    FJ_COMBINED_JOB_OK, FJ_COMBINED_JOB_FAILED, FJ_COMBINED_JOB_CANCELLED
} fj_combined_job_status_t;

/* Internal cooperative job; not connected to BACKUP/RESTORE. Initialize a
 * fresh job with init; never reinitialize a running job, cancel it first.
 * Caller owns all buffers and input snapshots until completion/cancellation,
 * must keep them distinct and stable, and must scrub input snapshots. Caller
 * must authorize, supply fresh random salt and unique nonce for each backup,
 * and cancel on lock/reset. KDF advances at most 512 iterations per step;
 * the final authenticated encryption/decryption is performed in one step. */
typedef struct {
    fj_combined_job_status_t status;
    fj_kdf_t kdf;
    bool sealing;
    const fj_backup_payload_t *keys_in;
    const fj_hmac_snapshot_t *hmac_in;
    fj_backup_payload_t *keys_out;
    fj_hmac_snapshot_t *hmac_out;
    const uint8_t *blob_in;
    uint8_t *blob_out, *workspace;
    uint8_t salt[16], nonce[12];
} fj_combined_password_job_t;

void fj_combined_job_init(fj_combined_password_job_t *job);
bool fj_combined_job_seal(fj_combined_password_job_t *job,
                          const fj_backup_payload_t *keys, const fj_hmac_snapshot_t *hmac,
                          const uint8_t *password, size_t password_len,
                          const uint8_t salt[16], const uint8_t nonce[12],
                          uint8_t *out, size_t out_len, uint8_t *workspace, size_t workspace_len);
bool fj_combined_job_open(fj_combined_password_job_t *job,
                          const uint8_t *blob, size_t blob_len,
                          const uint8_t *password, size_t password_len,
                          fj_backup_payload_t *keys, fj_hmac_snapshot_t *hmac,
                          uint8_t *workspace, size_t workspace_len);
/* Returns true only while work remains; inspect job->status on completion. */
bool fj_combined_job_step(fj_combined_password_job_t *job);
void fj_combined_job_cancel(fj_combined_password_job_t *job);
#endif
