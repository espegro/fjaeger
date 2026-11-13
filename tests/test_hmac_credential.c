#include <assert.h>
#include <stdio.h>
#include <string.h>
#include "hmac_credential.h"
void fj_random(void *buf, size_t n) { memset(buf, 0x42, n); }
static void is_zero(const uint8_t *p, size_t n) { for (size_t i=0; i<n; i++) assert(!p[i]); }
int main(void) {
    uint8_t root[32], wrong[32], secret[FJ_HMAC_MATERIAL_LEN], out[FJ_HMAC_MATERIAL_LEN];
    for (unsigned i=0;i<sizeof(root);i++) root[i]=(uint8_t)(i+1);
    memcpy(wrong,root,sizeof(root)); wrong[0]^=1;
    for (unsigned i=0;i<sizeof(secret);i++) secret[i]=(uint8_t)(i+3);
    fj_hmac_credential_t r={0};
    memset(r.credential_id,0x11,sizeof(r.credential_id));
    memset(r.rp_id_hash,0x22,sizeof(r.rp_id_hash));
    memset(r.public_key,0x33,sizeof(r.public_key));
    memset(r.nonce,0x44,sizeof(r.nonce));
    assert(fj_hmac_credential_seal(&r,root,secret));
    assert(memcmp(r.ciphertext,secret,sizeof(secret)) != 0);
    assert(fj_hmac_credential_open(&r,root,out));
    assert(memcmp(out,secret,sizeof(out)) == 0);
    assert(!fj_hmac_credential_open(&r,wrong,out)); is_zero(out,sizeof(out));
    r.rp_id_hash[0]^=1;
    assert(!fj_hmac_credential_open(&r,root,out)); is_zero(out,sizeof(out));
    r.rp_id_hash[0]^=1; r.credential_id[0]^=1;
    assert(!fj_hmac_credential_open(&r,root,out)); is_zero(out,sizeof(out));
    r.credential_id[0]^=1; r.public_key[0]^=1;
    assert(!fj_hmac_credential_open(&r,root,out)); is_zero(out,sizeof(out));
    r.public_key[0]^=1; r.ciphertext[0]^=1;
    assert(!fj_hmac_credential_open(&r,root,out)); is_zero(out,sizeof(out));
    r.ciphertext[0]^=1; r.tag[0]^=1;
    assert(!fj_hmac_credential_open(&r,root,out)); is_zero(out,sizeof(out));
    puts("hmac credential encryption tests: ok");
}
