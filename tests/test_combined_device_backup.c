#include <assert.h>
#include <stdio.h>
#include <string.h>
#include "combined_device_backup.h"
#include "combined_device_restore.h"
#include "combined_password_job.h"
#include "hmac_runtime.h"

static bool available=true, export_ok=true;
static fj_hmac_root_mode_t mode=FJ_HMAC_ROOT_DEVELOPMENT;
static fj_hmac_snapshot_t source;
static unsigned commits;
bool fj_restore_bundle(const fj_backup_payload_t *keys,const fj_hmac_snapshot_t *hmac,
                       const fj_restore_wraps_t *wraps,fj_hmac_root_mode_t m,
                       const uint8_t otp[32],const uint8_t salt[16],
                       const uint8_t nonce[12],const uint8_t id[16]) {
    (void)keys; (void)wraps; (void)otp; (void)salt; (void)nonce; (void)id;
    assert(m==FJ_HMAC_ROOT_DEVELOPMENT && !memcmp(hmac,&source,sizeof(source)));
    commits++; return true;
}
void fj_random(void *p,size_t n) { memset(p,0x42,n); }
bool fj_hmac_runtime_root_mode(fj_hmac_root_mode_t *out) {
    if (!available) return false;
    *out=mode; return true;
}
bool fj_hmac_store_export(fj_hmac_root_mode_t m,const uint8_t otp[32],fj_hmac_snapshot_t *out) {
    (void)otp; if (!export_ok || m!=mode) return false; *out=source; return true;
}
static fj_backup_payload_t keys, decoded;
static fj_hmac_snapshot_t restored;
static uint8_t blob[FJ_COMBINED_PASSWORD_SIZE],workspace[FJ_COMBINED_BACKUP_PAYLOAD];
int main(void) {
    uint8_t key[32]={1},salt[16]={2},nonce[12]={3},material[96]={4};
    keys.active_profile_valid=1; keys.profiles[0].in_use=true;
    keys.ctap2[0].in_use=true; keys.ctap2[0].credential_id[0]=1;
    source.root[0]=5; source.entries[0].used=1;
    source.entries[0].credential.credential_id[0]=2;
    assert(fj_hmac_credential_seal(&source.entries[0].credential,source.root,material));
    assert(fj_combined_device_backup(&keys,key,salt,nonce,blob,sizeof(blob)));
    assert(!memcmp(blob,"FJCP",4) && !memcmp(blob+8,salt,16));
    assert(fj_combined_backup_open(blob+FJ_COMBINED_PASSWORD_HEADER,FJ_COMBINED_BACKUP_SIZE,
                                   key,&decoded,&restored,workspace,sizeof(workspace)));
    assert(!memcmp(&keys,&decoded,sizeof(keys)) && !memcmp(&source,&restored,sizeof(source)));
    uint8_t wrong[32]={8},id[16]={9}; fj_restore_wraps_t wraps={0};
    assert(!fj_combined_device_restore_prepare(blob,sizeof(blob),wrong,&decoded));
    assert(fj_combined_device_restore_prepare(blob,sizeof(blob),key,&decoded));
    assert(!fj_combined_device_restore_prepare(blob,sizeof(blob),key,&keys));
    assert(!fj_combined_device_restore_commit(&keys,&wraps,salt,nonce,id));
    fj_combined_device_restore_cancel();
    assert(!fj_combined_device_restore_commit(&decoded,&wraps,salt,nonce,id));
    assert(fj_combined_device_restore_prepare(blob,sizeof(blob),key,&decoded));
    decoded.master[0]^=1;
    assert(!fj_combined_device_restore_commit(&decoded,&wraps,salt,nonce,id));
    assert(commits==0);
    assert(fj_combined_device_restore_prepare(blob,sizeof(blob),key,&decoded));
    assert(fj_combined_device_restore_commit(&decoded,&wraps,salt,nonce,id));
    assert(commits==1);
    assert(!fj_combined_device_restore_commit(&decoded,&wraps,salt,nonce,id));
    available=false;
    assert(!fj_combined_device_backup(&keys,key,salt,nonce,blob,sizeof(blob)));
    for (size_t i=0;i<sizeof(blob);i++) assert(blob[i]==0);
    available=true; mode=FJ_HMAC_ROOT_OTP;
    assert(!fj_combined_device_backup(&keys,key,salt,nonce,blob,sizeof(blob)));
    mode=FJ_HMAC_ROOT_DEVELOPMENT; export_ok=false;
    assert(!fj_combined_device_backup(&keys,key,salt,nonce,blob,sizeof(blob)));
    puts("combined device backup export and failure handling: ok");
}
