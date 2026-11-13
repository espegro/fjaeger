#include "restore_bundle.h"
#include "restore_prepared.h"
#include "keys_stage_internal.h"
#include "crypto.h"
#include "hmac_config.h"
#include <string.h>

bool fj_restore_bundle(const fj_backup_payload_t *keys,const fj_hmac_snapshot_t *hmac,
                       const fj_restore_wraps_t *wraps,fj_hmac_root_mode_t mode,
                       const uint8_t otp[32],const uint8_t root_salt[16],
                       const uint8_t root_nonce[12],const uint8_t transaction_id[16]) {
    fj_hmac_root_record_t root={0};
    uint8_t current_root[32]={0};
    fj_hmac_mode_t configured_policy;
    fj_hmac_root_mode_t configured_mode;
    uint8_t enc_pass[32]={0},enc_puk[32]={0}; bool ok=false, started=false;
    if (!keys || !hmac || !wraps || !root_salt || !root_nonce || !transaction_id ||
        !fj_combined_backup_pair_valid(keys,hmac) ||
        !fj_hmac_config_init() ||
        !fj_hmac_config_get(&configured_policy,&configured_mode) ||
        configured_mode!=mode || !fj_hmac_store_open_root(mode,otp,current_root) ||
        !fj_hmac_root_create(&root,mode,hmac->root,otp,root_salt,root_nonce)) goto done;
    for (unsigned i=0;i<32;i++) {
        enc_pass[i]=keys->master[i]^wraps->pass_wrap_key[i];
        enc_puk[i]=keys->master[i]^wraps->puk_wrap_key[i];
    }
    if (!fj_keys_restore_begin_transaction()) goto done;
    started=true;
    if (!fj_keys_backup_restore(keys) ||
        !fj_keys_set_passphrase(wraps->pass_hash,wraps->pass_salt) ||
        !fj_keys_set_master_pin_wrap(enc_pass,wraps->pass_wrap_salt) ||
        !fj_keys_set_puk(wraps->puk_hash,wraps->puk_salt) ||
        !fj_keys_set_master_puk_wrap(enc_puk,wraps->puk_wrap_salt)) goto done;
    /* This function consumes the in-memory transaction even on failure. */
    ok=fj_restore_prepared(hmac,&root,otp,transaction_id); started=false;
done:
    if (started) fj_store_abort();
    fj_secure_zero(enc_pass,sizeof(enc_pass)); fj_secure_zero(enc_puk,sizeof(enc_puk));
    fj_secure_zero(current_root,sizeof(current_root));
    fj_secure_zero(&root,sizeof(root)); return ok;
}
