#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "hardware/flash.h"
#include "hmac_store.h"
#include "hmac_credential.h"
#include "hmac_backup.h"
#include "crypto.h"
_Alignas(4) uint8_t test_flash[PICO_FLASH_SIZE_BYTES];
static bool fail_program;
static bool interrupt_erase_after_program, fail_next_erase;
void fj_random(void *p, size_t n) { memset(p,0x42,n); }
void flash_range_erase(uint32_t offset, size_t n) {
    assert(offset+n<=sizeof(test_flash));
    if (fail_next_erase) { n=64; fail_next_erase=false; }
    memset(test_flash+offset,0xff,n);
}
void flash_range_program(uint32_t offset, const uint8_t *p, size_t n) {
    assert(offset+n<=sizeof(test_flash)); if(fail_program) n=64;
    memcpy(test_flash+offset,p,n);
    if (interrupt_erase_after_program) { fail_next_erase=true; interrupt_erase_after_program=false; }
}
static bool all_erased(const uint8_t *p, size_t n) {
    for (size_t i=0;i<n;i++) if (p[i]!=0xff) return false;
    return true;
}
int main(void) {
    memset(test_flash,0xff,sizeof(test_flash));
    const size_t normal_store=PICO_FLASH_SIZE_BYTES-2*FLASH_SECTOR_SIZE-2*(32u*1024u);
    test_flash[normal_store]=0x5a; /* unrelated normal credential store */
    assert(fj_hmac_store_init());
    assert(fj_hmac_store_legacy_backup_safe());
    uint8_t root[32], material[FJ_HMAC_MATERIAL_LEN], out[FJ_HMAC_MATERIAL_LEN];
    memset(root,0x91,sizeof(root)); memset(material,0x72,sizeof(material));
    fj_hmac_credential_t record={0}, got;
    record.credential_id[0]=1; record.rp_id_hash[0]=2; record.nonce[0]=3;
    assert(fj_hmac_credential_seal(&record,root,material));
    assert(!fj_hmac_store_put(&record));
    uint8_t salt[16]={1}, nonce[12]={2}, otp[32]={3}, restored_root[32];
    fj_hmac_root_record_t protected_root;
    assert(fj_hmac_root_create(&protected_root,FJ_HMAC_ROOT_OTP,root,otp,salt,nonce));
    assert(!fj_hmac_store_provision_root(&protected_root,NULL));
    assert(fj_hmac_store_provision_root(&protected_root,otp));
    assert(!fj_hmac_store_legacy_backup_safe());
    assert(!fj_hmac_store_provision_root(&protected_root,otp));
    assert(!fj_hmac_store_open_root(FJ_HMAC_ROOT_OTP,NULL,restored_root));
    assert(!fj_hmac_store_open_root(FJ_HMAC_ROOT_DEVELOPMENT,NULL,restored_root));
    assert(fj_hmac_store_open_root(FJ_HMAC_ROOT_OTP,otp,restored_root));
    assert(memcmp(restored_root,root,32)==0);
    assert(fj_hmac_store_put(&record));
    fj_hmac_credential_info_t listed[FJ_HMAC_STORE_CAPACITY]; size_t count=99;
    assert(!fj_hmac_store_list(listed,0,&count));
    assert(fj_hmac_store_list(listed,FJ_HMAC_STORE_CAPACITY,&count) && count==1);
    assert(!memcmp(listed[0].credential_id,record.credential_id,16));
    assert(!memcmp(listed[0].rp_id_hash,record.rp_id_hash,32));
    assert(!fj_hmac_store_put(&record)); /* never overwrite an existing key */
    assert(fj_hmac_store_init());
    assert(fj_hmac_store_open_root(FJ_HMAC_ROOT_OTP,otp,restored_root));
    assert(memcmp(restored_root,root,32)==0);
    assert(fj_hmac_store_get(record.credential_id,&got));
    assert(fj_hmac_credential_open(&got,root,out));
    assert(memcmp(out,material,sizeof(out))==0);
    assert(test_flash[normal_store]==0x5a);
    fail_program=true; assert(!fj_hmac_store_remove(record.credential_id));
    assert(fj_hmac_store_get(record.credential_id,&got));
    fail_program=false; assert(fj_hmac_store_init());
    assert(fj_hmac_store_get(record.credential_id,&got));
    fj_hmac_credential_t other=record;
    other.credential_id[0]=4; other.nonce[0]=5;
    assert(fj_hmac_credential_seal(&other,root,material));
    assert(fj_hmac_store_put(&other));
    interrupt_erase_after_program=true;
    assert(!fj_hmac_store_remove(record.credential_id));
    assert(!fj_hmac_store_get(other.credential_id,&got)); /* fail closed */
    assert(fj_hmac_store_init()); /* finishes the interrupted erase */
    assert(!fj_hmac_store_get(record.credential_id,&got));
    assert(fj_hmac_store_get(other.credential_id,&got));
    assert(fj_hmac_store_list(listed,FJ_HMAC_STORE_CAPACITY,&count) && count==1);
    assert(!memcmp(listed[0].credential_id,other.credential_id,16));
    assert(fj_hmac_credential_open(&got,root,out));
    assert(memcmp(out,material,sizeof(out))==0);
    const size_t hmac_start=normal_store-2*FLASH_SECTOR_SIZE;
    assert(all_erased(test_flash+hmac_start,FLASH_SECTOR_SIZE) ||
           all_erased(test_flash+hmac_start+FLASH_SECTOR_SIZE,FLASH_SECTOR_SIZE));
    assert(fj_hmac_store_init());
    assert(!fj_hmac_store_get(record.credential_id,&got));
    assert(fj_hmac_store_get(other.credential_id,&got));
    assert(test_flash[normal_store]==0x5a);
    fj_hmac_snapshot_t snapshot, decoded;
    uint8_t backup[FJ_HMAC_BACKUP_SIZE], backup_key[32]={7}, backup_nonce[12]={8};
    assert(!fj_hmac_store_export(FJ_HMAC_ROOT_OTP,NULL,&snapshot));
    assert(fj_hmac_store_export(FJ_HMAC_ROOT_OTP,otp,&snapshot));
    assert(fj_hmac_backup_seal(&snapshot,backup_key,backup_nonce,backup,sizeof(backup)));
    assert(!fj_hmac_store_restore_empty(&snapshot,&protected_root,otp));
    fail_program=true; assert(!fj_hmac_store_wipe());
    fail_program=false; assert(fj_hmac_store_init());
    assert(fj_hmac_store_open_root(FJ_HMAC_ROOT_OTP,otp,restored_root));
    /* A power interruption while erasing the old slot must not resurrect it;
     * initialization completes the tombstone's cleanup. */
    interrupt_erase_after_program=true;
    assert(!fj_hmac_store_wipe());
    assert(!fj_hmac_store_open_root(FJ_HMAC_ROOT_OTP,otp,restored_root));
    assert(fj_hmac_store_init());
    assert(!fj_hmac_store_get(record.credential_id,&got));
    assert(!fj_hmac_store_open_root(FJ_HMAC_ROOT_OTP,otp,restored_root));
    assert(test_flash[normal_store]==0x5a);
    /* Recover on a device with a different OTP without changing responses. */
    uint8_t new_otp[32]={9}, wrap_salt[16]={10}, wrap_nonce[12]={11};
    fj_hmac_root_record_t replacement_root;
    assert(fj_hmac_backup_open(backup,sizeof(backup),backup_key,&decoded));
    assert(fj_hmac_root_create(&replacement_root,FJ_HMAC_ROOT_OTP,decoded.root,new_otp,wrap_salt,wrap_nonce));
    assert(!fj_hmac_store_restore_empty(&decoded,&replacement_root,otp));
    fail_program=true;
    assert(!fj_hmac_store_restore_empty(&decoded,&replacement_root,new_otp));
    fail_program=false;
    assert(fj_hmac_store_init());
    assert(!fj_hmac_store_open_root(FJ_HMAC_ROOT_OTP,new_otp,restored_root));
    assert(fj_hmac_store_restore_empty(&decoded,&replacement_root,new_otp));
    assert(fj_hmac_store_init());
    assert(!fj_hmac_store_open_root(FJ_HMAC_ROOT_OTP,otp,restored_root));
    assert(fj_hmac_store_open_root(FJ_HMAC_ROOT_OTP,new_otp,restored_root));
    assert(fj_hmac_store_get(other.credential_id,&got));
    assert(fj_hmac_credential_open(&got,restored_root,out));
    assert(memcmp(out,material,sizeof(out))==0);
    uint8_t challenge[32]={0x27}, before[32], after[32];
    assert(fj_hmac_sha256(material+64,32,challenge,32,before));
    assert(fj_hmac_sha256(out+64,32,challenge,32,after));
    assert(memcmp(before,after,32)==0);
    assert(fj_hmac_store_wipe());
    assert(fj_hmac_store_init());
    assert(!fj_hmac_store_open_root(FJ_HMAC_ROOT_OTP,otp,restored_root));
    /* An incomplete first provisioning fails closed after reboot. */
    memset(test_flash,0xff,sizeof(test_flash));
    assert(fj_hmac_store_init());
    fail_program=true;
    assert(!fj_hmac_store_provision_root(&protected_root,otp));
    fail_program=false;
    assert(!fj_hmac_store_init());
    memset(restored_root,0xa5,sizeof(restored_root));
    assert(!fj_hmac_store_open_root(FJ_HMAC_ROOT_OTP,otp,restored_root));
    for (unsigned i=0;i<sizeof(restored_root);i++) assert(restored_root[i]==0);
    puts("separate hmac store persistence and failure tests: ok");
}
