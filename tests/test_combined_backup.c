#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "combined_backup.h"

void fj_random(void *p,size_t n) { memset(p,0x42,n); }
static void zeroed(const void *p,size_t n) {
    const uint8_t *b=p; for (size_t i=0;i<n;i++) assert(b[i]==0);
}
static fj_backup_payload_t keys, decoded_keys;
static fj_hmac_snapshot_t hmac, decoded_hmac;
static uint8_t workspace[FJ_COMBINED_BACKUP_PAYLOAD];
static uint8_t blob[FJ_COMBINED_BACKUP_SIZE], other[FJ_COMBINED_BACKUP_SIZE];
int main(void) {
    uint8_t key[32]={1}, wrong[32]={2}, nonce[12]={3}, material[96]={4}, opened[96];
    keys.active_profile_valid=1; keys.profiles[0].in_use=true;
    memcpy(keys.profiles[0].name,"Default",8); keys.master[0]=0x42;
    keys.ctap2[0].in_use=true; keys.ctap2[0].credential_id[0]=0x61;
    hmac.root[0]=0x31; hmac.entries[0].used=1;
    hmac.entries[0].credential.credential_id[0]=0x52;
    assert(fj_hmac_credential_seal(&hmac.entries[0].credential,hmac.root,material));
    assert(fj_combined_backup_pair_valid(&keys,&hmac));
    memcpy(keys.ctap2[0].credential_id,hmac.entries[0].credential.credential_id,FJ_CRED_ID_LEN);
    assert(!fj_combined_backup_pair_valid(&keys,&hmac));
    assert(!fj_combined_backup_seal(&keys,&hmac,key,nonce,blob,sizeof(blob),workspace,sizeof(workspace)));
    keys.ctap2[0].credential_id[0]=0x61;
    assert(fj_combined_backup_seal(&keys,&hmac,key,nonce,blob,sizeof(blob),workspace,sizeof(workspace)));
    zeroed(workspace,sizeof(workspace));
    assert(fj_combined_backup_open(blob,sizeof(blob),key,&decoded_keys,&decoded_hmac,workspace,sizeof(workspace)));
    assert(memcmp(&keys,&decoded_keys,sizeof(keys))==0);
    assert(fj_hmac_credential_open(&decoded_hmac.entries[0].credential,decoded_hmac.root,opened));
    assert(memcmp(material,opened,sizeof(material))==0); zeroed(workspace,sizeof(workspace));
    assert(!fj_combined_backup_open(blob,sizeof(blob),wrong,&decoded_keys,&decoded_hmac,workspace,sizeof(workspace)));
    zeroed(&decoded_keys,sizeof(decoded_keys)); zeroed(&decoded_hmac,sizeof(decoded_hmac));
    memcpy(other,blob,sizeof(blob)); other[16]^=1;
    assert(!fj_combined_backup_open(other,sizeof(other),key,&decoded_keys,&decoded_hmac,workspace,sizeof(workspace)));
    memcpy(other,blob,sizeof(blob)); other[FJ_COMBINED_BACKUP_HEADER+100]^=1;
    assert(!fj_combined_backup_open(other,sizeof(other),key,&decoded_keys,&decoded_hmac,workspace,sizeof(workspace)));
    memcpy(other,blob,sizeof(blob)); other[sizeof(other)-1]^=1;
    assert(!fj_combined_backup_open(other,sizeof(other),key,&decoded_keys,&decoded_hmac,workspace,sizeof(workspace)));
    assert(!fj_combined_backup_open(blob,sizeof(blob)-1,key,&decoded_keys,&decoded_hmac,workspace,sizeof(workspace)));
    zeroed(&decoded_keys,sizeof(decoded_keys)); zeroed(&decoded_hmac,sizeof(decoded_hmac));
    zeroed(workspace,sizeof(workspace));
    nonce[0]++; hmac.root[0]^=1;
    assert(!fj_combined_backup_seal(&keys,&hmac,key,nonce,other,sizeof(other),workspace,sizeof(workspace)));
    zeroed(other,sizeof(other)); zeroed(workspace,sizeof(workspace));
    hmac.root[0]^=1; keys.ctap2[0].profile_id=1;
    assert(!fj_combined_backup_seal(&keys,&hmac,key,nonce,other,sizeof(other),workspace,sizeof(workspace)));
    keys.ctap2[0].profile_id=0;
    assert(fj_combined_backup_seal(&keys,&hmac,key,nonce,other,sizeof(other),workspace,sizeof(workspace)));
    memcpy(other+FJ_COMBINED_BACKUP_HEADER,blob+FJ_COMBINED_BACKUP_HEADER,100);
    assert(!fj_combined_backup_open(other,sizeof(other),key,&decoded_keys,&decoded_hmac,workspace,sizeof(workspace)));
    puts("combined backup authenticated round trip and corruption: ok");
}
