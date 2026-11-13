#include "combined_device_backup.h"
#include "combined_password_job.h"
#include "hmac_runtime.h"
#include "hmac_store.h"
#include "crypto.h"
#include <string.h>

/* Synchronous on the main core; no USB task may re-enter this workspace. */
static uint8_t workspace[FJ_COMBINED_BACKUP_PAYLOAD];
static fj_hmac_snapshot_t snapshot;

bool fj_combined_device_backup(const fj_backup_payload_t *keys,
                               const uint8_t key[32],const uint8_t salt[16],
                               const uint8_t nonce[12],uint8_t *out,size_t cap) {
    if (!keys || !key || !salt || !nonce || !out || cap<FJ_COMBINED_PASSWORD_SIZE) return false;
    fj_hmac_root_mode_t mode;
    bool ok=fj_hmac_runtime_root_mode(&mode) && mode==FJ_HMAC_ROOT_DEVELOPMENT &&
            fj_hmac_store_export(mode,NULL,&snapshot) &&
            fj_combined_backup_seal(keys,&snapshot,key,nonce,out+FJ_COMBINED_PASSWORD_HEADER,
                                    cap-FJ_COMBINED_PASSWORD_HEADER,workspace,sizeof(workspace));
    if (ok) {
        memcpy(out,"FJCP",4); out[4]=1; memset(out+5,0,3); memcpy(out+8,salt,16);
    } else fj_secure_zero(out,FJ_COMBINED_PASSWORD_SIZE);
    fj_secure_zero(&snapshot,sizeof(snapshot));
    fj_secure_zero(workspace,sizeof(workspace));
    return ok;
}
