#include <assert.h>
#include <stdio.h>
#include <string.h>
#include "hmac_root.h"
#include "hmac_credential.h"
void fj_random(void *buf, size_t n) { memset(buf, 0x42, n); }
static void zero(const uint8_t *p, size_t n) { for(size_t i=0;i<n;i++) assert(p[i]==0); }
int main(void) {
    uint8_t root[32], otp[32], wrong[32], salt[16], nonce[12], out[32];
    memset(root,0x13,sizeof(root)); memset(otp,0x24,sizeof(otp));
    memcpy(wrong,otp,sizeof(wrong)); wrong[0]^=1;
    memset(salt,0x35,sizeof(salt)); memset(nonce,0x46,sizeof(nonce));
    fj_hmac_root_record_t dev, protected, copy;
    assert(fj_hmac_root_create(&dev,FJ_HMAC_ROOT_DEVELOPMENT,root,NULL,salt,nonce));
    assert(fj_hmac_root_open(&dev,FJ_HMAC_ROOT_DEVELOPMENT,NULL,out));
    assert(memcmp(out,root,32)==0);
    assert(fj_hmac_root_create(&protected,FJ_HMAC_ROOT_OTP,root,otp,salt,nonce));
    assert(memcmp(protected.wrapped_root,root,32)!=0);
    assert(fj_hmac_root_open(&protected,FJ_HMAC_ROOT_OTP,otp,out));
    assert(memcmp(out,root,32)==0);
    assert(!fj_hmac_root_open(&protected,FJ_HMAC_ROOT_OTP,NULL,out)); zero(out,32);
    assert(!fj_hmac_root_open(&protected,FJ_HMAC_ROOT_OTP,wrong,out)); zero(out,32);
    assert(!fj_hmac_root_open(&protected,FJ_HMAC_ROOT_DEVELOPMENT,NULL,out)); zero(out,32);
    copy=protected; copy.mode=FJ_HMAC_ROOT_DEVELOPMENT;
    assert(!fj_hmac_root_open(&copy,FJ_HMAC_ROOT_OTP,otp,out)); zero(out,32);
    copy=protected; copy.salt[0]^=1;
    assert(!fj_hmac_root_open(&copy,FJ_HMAC_ROOT_OTP,otp,out)); zero(out,32);
    copy=protected; copy.nonce[0]^=1;
    assert(!fj_hmac_root_open(&copy,FJ_HMAC_ROOT_OTP,otp,out)); zero(out,32);
    copy=protected; copy.wrapped_root[0]^=1;
    assert(!fj_hmac_root_open(&copy,FJ_HMAC_ROOT_OTP,otp,out)); zero(out,32);
    copy=protected; copy.tag[0]^=1;
    assert(!fj_hmac_root_open(&copy,FJ_HMAC_ROOT_OTP,otp,out)); zero(out,32);
    /* Explicit dev -> OTP rewrap keeps existing credential material usable. */
    fj_hmac_credential_t cred={0}; uint8_t material[FJ_HMAC_MATERIAL_LEN], recovered[FJ_HMAC_MATERIAL_LEN];
    memset(material,0x57,sizeof(material)); cred.credential_id[0]=1; cred.nonce[0]=2;
    assert(fj_hmac_credential_seal(&cred,root,material));
    assert(fj_hmac_root_open(&protected,FJ_HMAC_ROOT_OTP,otp,out));
    assert(fj_hmac_credential_open(&cred,out,recovered));
    assert(memcmp(material,recovered,sizeof(material))==0);
    puts("hmac root protection and explicit rewrap tests: ok");
}
