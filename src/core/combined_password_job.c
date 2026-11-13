#include "combined_password_job.h"
#include <string.h>

void fj_combined_job_init(fj_combined_password_job_t *j) {
    if (j) fj_secure_zero(j,sizeof(*j));
}
static bool password_ok(const uint8_t *p,size_t n) { return p && n>=8 && n<=64; }
static void finish(fj_combined_password_job_t *j,fj_combined_job_status_t status) {
    if (status!=FJ_COMBINED_JOB_OK) {
        if (j->sealing && j->blob_out) fj_secure_zero(j->blob_out,FJ_COMBINED_PASSWORD_SIZE);
        if (!j->sealing && j->keys_out) fj_secure_zero(j->keys_out,sizeof(*j->keys_out));
        if (!j->sealing && j->hmac_out) fj_secure_zero(j->hmac_out,sizeof(*j->hmac_out));
    }
    if (j->workspace) fj_secure_zero(j->workspace,FJ_COMBINED_BACKUP_PAYLOAD);
    fj_secure_zero(j,sizeof(*j)); j->status=status;
}
bool fj_combined_job_seal(fj_combined_password_job_t *j,
                          const fj_backup_payload_t *keys,const fj_hmac_snapshot_t *hmac,
                          const uint8_t *password,size_t password_len,
                          const uint8_t salt[16],const uint8_t nonce[12],
                          uint8_t *out,size_t out_len,uint8_t *workspace,size_t workspace_len) {
    if (!j || j->status!=FJ_COMBINED_JOB_IDLE || !keys || !hmac ||
        !password_ok(password,password_len) || !salt || !nonce || !out ||
        out_len<FJ_COMBINED_PASSWORD_SIZE || !workspace || workspace_len<FJ_COMBINED_BACKUP_PAYLOAD) return false;
    j->sealing=true; j->keys_in=keys; j->hmac_in=hmac; j->blob_out=out; j->workspace=workspace;
    memcpy(j->salt,salt,16); memcpy(j->nonce,nonce,12);
    fj_secure_zero(out,FJ_COMBINED_PASSWORD_SIZE);
    fj_secure_zero(workspace,FJ_COMBINED_BACKUP_PAYLOAD);
    if (!fj_kdf_begin(&j->kdf,password,password_len,j->salt,16,FJ_PBKDF2_ITERATIONS)) {
        finish(j,FJ_COMBINED_JOB_FAILED); return false;
    }
    j->status=FJ_COMBINED_JOB_RUNNING; return true;
}
bool fj_combined_job_open(fj_combined_password_job_t *j,
                          const uint8_t *blob,size_t blob_len,
                          const uint8_t *password,size_t password_len,
                          fj_backup_payload_t *keys,fj_hmac_snapshot_t *hmac,
                          uint8_t *workspace,size_t workspace_len) {
    if (!j || j->status!=FJ_COMBINED_JOB_IDLE || !keys || !hmac) return false;
    fj_secure_zero(keys,sizeof(*keys)); fj_secure_zero(hmac,sizeof(*hmac));
    if (!blob || blob_len!=FJ_COMBINED_PASSWORD_SIZE ||
        memcmp(blob,"FJCP",4) || blob[4]!=1 || blob[5] || blob[6] || blob[7] ||
        !password_ok(password,password_len) ||
        !workspace || workspace_len<FJ_COMBINED_BACKUP_PAYLOAD) return false;
    j->sealing=false; j->blob_in=blob; j->keys_out=keys; j->hmac_out=hmac; j->workspace=workspace;
    memcpy(j->salt,blob+8,16);
    fj_secure_zero(workspace,FJ_COMBINED_BACKUP_PAYLOAD);
    if (!fj_kdf_begin(&j->kdf,password,password_len,j->salt,16,FJ_PBKDF2_ITERATIONS)) {
        finish(j,FJ_COMBINED_JOB_FAILED); return false;
    }
    j->status=FJ_COMBINED_JOB_RUNNING; return true;
}
bool fj_combined_job_step(fj_combined_password_job_t *j) {
    if (!j || j->status!=FJ_COMBINED_JOB_RUNNING) return false;
    for (unsigned i=0;i<FJ_COMBINED_KDF_STEPS_PER_TICK && j->kdf.running;i++) fj_kdf_step(&j->kdf);
    if (j->kdf.running) return true;
    uint8_t key[32]={0}; bool ok=fj_kdf_result(&j->kdf,key);
    if (ok && j->sealing) {
        ok=fj_combined_backup_seal(j->keys_in,j->hmac_in,key,j->nonce,
                                   j->blob_out+FJ_COMBINED_PASSWORD_HEADER,FJ_COMBINED_BACKUP_SIZE,
                                   j->workspace,FJ_COMBINED_BACKUP_PAYLOAD);
        if (ok) {
            memcpy(j->blob_out,"FJCP",4); j->blob_out[4]=1;
            memset(j->blob_out+5,0,3); memcpy(j->blob_out+8,j->salt,16);
        }
    } else if (ok) {
        ok=fj_combined_backup_open(j->blob_in+FJ_COMBINED_PASSWORD_HEADER,FJ_COMBINED_BACKUP_SIZE,
                                   key,j->keys_out,j->hmac_out,j->workspace,FJ_COMBINED_BACKUP_PAYLOAD);
    }
    fj_secure_zero(key,sizeof(key)); finish(j,ok ? FJ_COMBINED_JOB_OK : FJ_COMBINED_JOB_FAILED);
    return false;
}
void fj_combined_job_cancel(fj_combined_password_job_t *j) {
    if (j && j->status==FJ_COMBINED_JOB_RUNNING) finish(j,FJ_COMBINED_JOB_CANCELLED);
}
