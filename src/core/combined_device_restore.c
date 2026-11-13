#include "combined_device_restore.h"
#include "combined_password_job.h"
#include "hmac_runtime.h"
#include "crypto.h"
#include <string.h>

static uint8_t workspace[FJ_COMBINED_BACKUP_PAYLOAD];
static fj_hmac_snapshot_t snapshot;
static const fj_backup_payload_t *prepared_keys;
static uint8_t keys_digest[32];

void fj_combined_device_restore_cancel(void) {
    prepared_keys=NULL;
    fj_secure_zero(&snapshot,sizeof(snapshot));
    fj_secure_zero(keys_digest,sizeof(keys_digest));
    fj_secure_zero(workspace,sizeof(workspace));
}
bool fj_combined_device_restore_prepare(const uint8_t *blob,size_t len,
                                         const uint8_t key[32],fj_backup_payload_t *keys) {
    if (prepared_keys || !keys) return false;
    fj_secure_zero(keys,sizeof(*keys));
    if (!blob || len!=FJ_COMBINED_PASSWORD_SIZE || !key || memcmp(blob,"FJCP",4) ||
        blob[4]!=1 || blob[5] || blob[6] || blob[7]) return false;
    if (!fj_combined_backup_open(blob+FJ_COMBINED_PASSWORD_HEADER,FJ_COMBINED_BACKUP_SIZE,
                                 key,keys,&snapshot,workspace,sizeof(workspace))) {
        fj_combined_device_restore_cancel(); return false;
    }
    fj_sha256((const uint8_t *)keys,sizeof(*keys),keys_digest);
    prepared_keys=keys; return true;
}
bool fj_combined_device_restore_commit(const fj_backup_payload_t *keys,
                                       const fj_restore_wraps_t *wraps,
                                       const uint8_t salt[16],const uint8_t nonce[12],
                                       const uint8_t transaction_id[16]) {
    if (!prepared_keys || keys!=prepared_keys) return false;
    fj_hmac_root_mode_t mode;
    uint8_t digest[32]; fj_sha256((const uint8_t *)keys,sizeof(*keys),digest);
    bool ok=fj_ct_equal(digest,keys_digest,sizeof(digest)) &&
            fj_hmac_runtime_root_mode(&mode) && mode==FJ_HMAC_ROOT_DEVELOPMENT &&
            fj_restore_bundle(keys,&snapshot,wraps,mode,NULL,salt,nonce,transaction_id);
    fj_secure_zero(digest,sizeof(digest));
    fj_combined_device_restore_cancel();
    return ok;
}
