#include <assert.h>
#include <stdio.h>
#include <string.h>
#include "hmac_backup.h"
#include "hmac_root.h"
void fj_random(void *p,size_t n) { memset(p,0x42,n); }
static void empty(const void *p,size_t n) { const uint8_t *b=p; for(size_t i=0;i<n;i++) assert(!b[i]); }
int main(void) {
    fj_hmac_snapshot_t src={0}, dst;
    uint8_t key[32]={1}, bad[32]={2}, nonce[12]={3}, material[96], out[96];
    uint8_t blob[FJ_HMAC_BACKUP_SIZE], corrupted[FJ_HMAC_BACKUP_SIZE];
    memset(src.root,0x41,sizeof(src.root)); memset(material,0x73,sizeof(material));
    src.entries[1].used=1; src.entries[1].credential.credential_id[0]=9;
    src.entries[1].credential.rp_id_hash[0]=8; src.entries[1].credential.nonce[0]=7;
    assert(fj_hmac_credential_seal(&src.entries[1].credential,src.root,material));
    assert(fj_hmac_backup_seal(&src,key,nonce,blob,sizeof(blob)));
    assert(fj_hmac_backup_open(blob,sizeof(blob),key,&dst));
    assert(fj_hmac_credential_open(&dst.entries[1].credential,dst.root,out));
    assert(memcmp(out,material,sizeof(out))==0);
    assert(!fj_hmac_backup_open(blob,sizeof(blob),bad,&dst)); empty(&dst,sizeof(dst));
    memcpy(corrupted,blob,sizeof(blob)); corrupted[8]^=1;
    assert(!fj_hmac_backup_open(corrupted,sizeof(corrupted),key,&dst)); empty(&dst,sizeof(dst));
    memcpy(corrupted,blob,sizeof(blob)); corrupted[25]^=1;
    assert(!fj_hmac_backup_open(corrupted,sizeof(corrupted),key,&dst)); empty(&dst,sizeof(dst));
    memcpy(corrupted,blob,sizeof(blob)); corrupted[sizeof(blob)-1]^=1;
    assert(!fj_hmac_backup_open(corrupted,sizeof(corrupted),key,&dst)); empty(&dst,sizeof(dst));
    assert(!fj_hmac_backup_open(blob,sizeof(blob)-1,key,&dst)); empty(&dst,sizeof(dst));
    src.entries[2]=src.entries[1];
    assert(!fj_hmac_backup_seal(&src,key,nonce,blob,sizeof(blob)));
    src.entries[2].used=0; src.entries[1].credential.tag[0]^=1;
    assert(!fj_hmac_backup_seal(&src,key,nonce,blob,sizeof(blob)));
    /* Restore the exact root under a different device secret. */
    uint8_t otp[32]={5}, salt[16]={6}, wrap_nonce[12]={7}, recovered_root[32];
    fj_hmac_root_record_t wrapped;
    assert(fj_hmac_backup_open(blob,sizeof(blob),key,&dst));
    assert(fj_hmac_root_create(&wrapped,FJ_HMAC_ROOT_OTP,dst.root,otp,salt,wrap_nonce));
    assert(fj_hmac_root_open(&wrapped,FJ_HMAC_ROOT_OTP,otp,recovered_root));
    assert(fj_hmac_credential_open(&dst.entries[1].credential,recovered_root,out));
    assert(memcmp(out,material,sizeof(out))==0);
    puts("hmac backup encryption, authentication and cross-root tests: ok");
}
