#include <assert.h>
#include <stdio.h>
#include <string.h>
#include "hmac_backup_password.h"
#include "hmac_root.h"
void fj_random(void *p,size_t n) { memset(p,0x42,n); }
static void empty(const void *p,size_t n) { const uint8_t *b=p; for(size_t i=0;i<n;i++) assert(!b[i]); }
int main(void) {
    fj_hmac_snapshot_t a={0}, b;
    uint8_t salt[16]={1}, nonce[12]={2}, plaintext[96], recovered[96];
    uint8_t blob[FJ_HMAC_PASSWORD_BACKUP_SIZE], corrupt[FJ_HMAC_PASSWORD_BACKUP_SIZE];
    const uint8_t password[]="correct horse battery";
    memset(a.root,0x33,32); memset(plaintext,0x44,96);
    a.entries[0].used=1; a.entries[0].credential.credential_id[0]=8;
    a.entries[0].credential.nonce[0]=3;
    assert(fj_hmac_credential_seal(&a.entries[0].credential,a.root,plaintext));
    assert(fj_hmac_password_backup_seal(&a,password,sizeof(password)-1,salt,nonce,blob,sizeof(blob)));
    assert(fj_hmac_password_backup_open(blob,sizeof(blob),password,sizeof(password)-1,&b));
    assert(fj_hmac_credential_open(&b.entries[0].credential,b.root,recovered));
    assert(memcmp(recovered,plaintext,sizeof(plaintext))==0);
    const uint8_t wrong[]="incorrect password";
    assert(!fj_hmac_password_backup_open(blob,sizeof(blob),wrong,sizeof(wrong)-1,&b)); empty(&b,sizeof(b));
    memcpy(corrupt,blob,sizeof(blob)); corrupt[8]^=1;
    assert(!fj_hmac_password_backup_open(corrupt,sizeof(corrupt),password,sizeof(password)-1,&b)); empty(&b,sizeof(b));
    memcpy(corrupt,blob,sizeof(blob)); corrupt[sizeof(blob)-2]^=1;
    assert(!fj_hmac_password_backup_open(corrupt,sizeof(corrupt),password,sizeof(password)-1,&b)); empty(&b,sizeof(b));
    assert(!fj_hmac_password_backup_open(blob,sizeof(blob)-1,password,sizeof(password)-1,&b)); empty(&b,sizeof(b));
    assert(!fj_hmac_password_backup_seal(&a,(const uint8_t *)"short",5,salt,nonce,corrupt,sizeof(corrupt)));
    puts("hmac password backup KDF and corruption tests: ok");
}
