#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "hardware/flash.h"
#include "keys_stage.h"
#include "hmac_store.h"
#include "hmac_config.h"
#include "flash_layout.h"
#include "restore_boot.h"
#include "restore_prepared.h"
#include "restore_bundle.h"
#include "combined_password_job.h"
#include "combined_device_restore.h"

bool fj_hmac_runtime_root_mode(fj_hmac_root_mode_t *mode) {
    if (!mode) return false;
    *mode=FJ_HMAC_ROOT_DEVELOPMENT; return true;
}

_Alignas(4) uint8_t test_flash[PICO_FLASH_SIZE_BYTES];
static bool cut_program;
static uint32_t cut_program_offset=UINT32_MAX;
static uint32_t cut_erase_offset=UINT32_MAX;
void flash_range_erase(uint32_t off,size_t n) {
    assert(off+n<=sizeof(test_flash));
    if (off==cut_erase_offset) n=64;
    memset(test_flash+off,0xff,n);
}
void flash_range_program(uint32_t off,const uint8_t *p,size_t n) {
    assert(off+n<=sizeof(test_flash)); if (cut_program || off==cut_program_offset) n=64;
    memcpy(test_flash+off,p,n);
}
#include "../src/core/keys.c"

static void exercise(bool existing_hmac, bool cut_keys, bool cut_hmac) {
    memset(test_flash,0xff,sizeof(test_flash));
    assert(fj_restore_journal_init());
    fj_keys_init(); assert(fj_keys_ready()); assert(fj_keys_set_timeout(123));
    assert(fj_hmac_store_init());
    uint8_t root[32]={1}, otp[32]={2}, salt[16]={3}, nonce[12]={4};
    fj_hmac_root_record_t wrapped;
    assert(fj_hmac_root_create(&wrapped,FJ_HMAC_ROOT_OTP,root,otp,salt,nonce));
    if (existing_hmac) assert(fj_hmac_store_provision_root(&wrapped,otp));
    fj_hmac_snapshot_t snapshot={0}; memcpy(snapshot.root,root,32);
    uint8_t material[FJ_HMAC_MATERIAL_LEN]={5};
    snapshot.entries[0].used=1; snapshot.entries[0].credential.credential_id[0]=6;
    snapshot.entries[0].credential.nonce[0]=7;
    assert(fj_hmac_credential_seal(&snapshot.entries[0].credential,root,material));
    fj_restore_plan_t plan={0}; plan.transaction_id[0]=8;
    plan.old_keys_generation=active_generation; plan.new_keys_generation=active_generation+1;
    plan.old_hmac_generation=existing_hmac ? 1 : 0;
    plan.new_hmac_generation=plan.old_hmac_generation+1;
    fj_store_begin(); assert(fj_keys_set_timeout(456));
    assert(fj_keys_stage_digest(&plan,plan.new_keys_digest));
    assert(fj_hmac_stage_digest(&snapshot,&wrapped,otp,&plan,plan.new_hmac_digest));
    assert(fj_restore_journal_begin(&plan));
    assert(fj_keys_stage_write(&plan));
    assert(fj_hmac_stage_write(&snapshot,&wrapped,otp,&plan));
    fj_store_abort();
    assert(!fj_keys_stage_activate(&plan)); assert(!fj_hmac_stage_activate(&plan));
    assert(fj_restore_journal_commit());
    fj_restore_plan_t wrong=plan; wrong.new_hmac_digest[0]^=1;
    assert(!fj_keys_stage_activate(&wrong)); assert(!fj_hmac_stage_activate(&wrong));
    if (cut_keys) {
        cut_program=true; assert(!fj_keys_stage_activate(&plan)); cut_program=false;
        assert(fj_restore_journal_init());
    }
    assert(fj_keys_stage_activate(&plan));
    assert(fj_keys_stage_activate(&plan));
    assert(fj_keys_stage_verify(&plan));
    if (cut_hmac) {
        cut_program=true; assert(!fj_hmac_stage_activate(&plan)); cut_program=false;
        assert(fj_restore_journal_init());
    }
    assert(fj_hmac_stage_activate(&plan));
    assert(fj_hmac_stage_activate(&plan));
    assert(fj_hmac_stage_verify(&plan));
    assert(fj_keys_restore_new_active(&plan) && fj_hmac_restore_new_active(&plan));
    assert(fj_restore_journal_finalize());
    assert(fj_keys_restore_discard_previous(&plan));
    assert(fj_hmac_restore_discard_previous(&plan));
    assert(fj_keys_stage_discard() && fj_hmac_stage_discard());
    assert(fj_keys_restore_new_active(&plan) && fj_hmac_restore_new_active(&plan));
    assert(fj_restore_journal_finish());
    fj_keys_init(); uint32_t timeout=0;
    assert(fj_keys_get_timeout(&timeout) && timeout==456);
    assert(fj_hmac_store_init()); fj_hmac_credential_t got;
    assert(fj_hmac_store_get(snapshot.entries[0].credential.credential_id,&got));
    assert(!fj_keys_stage_activate(&plan)); assert(!fj_hmac_stage_activate(&plan));
}
static void boot_recovery(void) {
    memset(test_flash,0xff,sizeof(test_flash));
    assert(fj_restore_boot_recover());
    fj_keys_init(); assert(fj_keys_ready());
    assert(fj_hmac_store_init());
    uint8_t root[32]={11}, otp[32]={12}, salt[16]={13}, nonce[12]={14};
    fj_hmac_root_record_t wrapped;
    assert(fj_hmac_root_create(&wrapped,FJ_HMAC_ROOT_OTP,root,otp,salt,nonce));
    assert(fj_hmac_store_provision_root(&wrapped,otp));
    fj_hmac_snapshot_t snapshot={0}; memcpy(snapshot.root,root,32);
    fj_restore_plan_t plan={0}; plan.transaction_id[0]=15;
    plan.old_keys_generation=active_generation; plan.new_keys_generation=active_generation+1;
    plan.old_hmac_generation=1; plan.new_hmac_generation=2;
    fj_store_begin(); assert(fj_keys_set_timeout(789));
    assert(fj_keys_stage_digest(&plan,plan.new_keys_digest));
    assert(fj_hmac_stage_digest(&snapshot,&wrapped,otp,&plan,plan.new_hmac_digest));
    assert(fj_restore_journal_begin(&plan));
    assert(fj_keys_stage_write(&plan));
    fj_store_abort();
    size_t active_offset=FLASH_OFFSET_BYTES+(unsigned)active_copy*STORE_SLOT_SIZE;
    test_flash[active_offset+20]^=1;
    assert(!fj_restore_boot_recover()); /* no trustworthy old pair */
    test_flash[active_offset+20]^=1;
    assert(fj_restore_boot_recover()); /* PREPARED rolls back */
    fj_restore_phase_t phase; fj_restore_plan_t current;
    assert(fj_restore_journal_read(&phase,&current) && phase==FJ_RESTORE_CLEAN);
    fj_keys_init(); uint32_t timeout=0;
    assert(!fj_keys_get_timeout(&timeout) || timeout!=789);
    fj_store_begin(); assert(fj_keys_set_timeout(789));
    assert(fj_restore_journal_begin(&plan));
    assert(fj_keys_stage_write(&plan));
    assert(fj_hmac_stage_write(&snapshot,&wrapped,otp,&plan));
    fj_store_abort(); assert(fj_restore_journal_commit());
    test_flash[FJ_HMAC_STAGE_OFFSET+100]^=1;
    assert(!fj_restore_boot_recover()); /* committed copy is damaged */
    test_flash[FJ_HMAC_STAGE_OFFSET+100]^=1;
    cut_program=true; assert(!fj_restore_boot_recover()); cut_program=false;
    assert(fj_restore_journal_read(&phase,&current) && phase==FJ_RESTORE_COMMITTED);
    cut_erase_offset=(uint32_t)active_offset;
    assert(!fj_restore_boot_recover());
    assert(fj_restore_journal_read(&phase,&current) && phase==FJ_RESTORE_FINALIZING);
    assert(fj_keys_restore_new_active(&plan) && fj_hmac_restore_new_active(&plan));
    cut_erase_offset=FJ_HMAC_STORE_OFFSET;
    assert(!fj_restore_boot_recover());
    assert(fj_keys_restore_new_active(&plan) && fj_hmac_restore_new_active(&plan));
    cut_erase_offset=FJ_HMAC_STAGE_OFFSET;
    assert(!fj_restore_boot_recover());
    cut_erase_offset=UINT32_MAX;
    assert(fj_restore_journal_read(&phase,&current) && phase==FJ_RESTORE_FINALIZING);
    assert(fj_keys_restore_new_active(&plan) && fj_hmac_restore_new_active(&plan));
    assert(fj_restore_boot_recover());
    assert(fj_restore_journal_read(&phase,&current) && phase==FJ_RESTORE_CLEAN);
    for (size_t i=0;i<FJ_KEYS_SLOT_SIZE;i++) assert(test_flash[FJ_KEYS_STAGE_OFFSET+i]==0xff);
    for (size_t i=0;i<FLASH_SECTOR_SIZE;i++) assert(test_flash[FJ_HMAC_STAGE_OFFSET+i]==0xff);
    for (size_t i=0;i<STORE_SLOT_SIZE;i++) assert(test_flash[active_offset+i]==0xff);
    for (size_t i=0;i<FLASH_SECTOR_SIZE;i++) assert(test_flash[FJ_HMAC_STORE_OFFSET+i]==0xff);
    fj_keys_init(); assert(fj_keys_get_timeout(&timeout) && timeout==789);
    assert(fj_hmac_store_init()); uint8_t opened[32];
    assert(fj_hmac_store_open_root(FJ_HMAC_ROOT_OTP,otp,opened));
    assert(memcmp(opened,root,32)==0);
    /* Unrecognized journal bytes must not open normal service. */
    memset(test_flash,0xff,sizeof(test_flash));
    test_flash[FJ_RESTORE_JOURNAL_OFFSET]=0;
    assert(!fj_restore_boot_recover());
    memset(test_flash,0xff,sizeof(test_flash));
    test_flash[FJ_KEYS_STAGE_OFFSET+100]=0;
    assert(fj_restore_journal_init()); assert(fj_restore_journal_begin_wipe());
    cut_erase_offset=FJ_KEYS_STAGE_OFFSET;
    assert(!fj_restore_boot_recover());
    cut_erase_offset=UINT32_MAX;
    assert(fj_restore_boot_recover());
    assert(test_flash[FJ_KEYS_STAGE_OFFSET+100]==0xff);
}
static void prepared_restore(unsigned cut) {
    memset(test_flash,0xff,sizeof(test_flash));
    assert(fj_restore_boot_recover());
    fj_keys_init(); assert(fj_keys_ready()); assert(fj_keys_set_timeout(111));
    assert(fj_hmac_store_init());
    uint8_t old_root[32]={1}, new_root[32]={2}, otp[32]={3}, salt[16]={4}, nonce[12]={5};
    fj_hmac_root_record_t old_wrap,new_wrap;
    assert(fj_hmac_root_create(&old_wrap,FJ_HMAC_ROOT_OTP,old_root,otp,salt,nonce));
    nonce[0]++;
    assert(fj_hmac_root_create(&new_wrap,FJ_HMAC_ROOT_OTP,new_root,otp,salt,nonce));
    assert(fj_hmac_store_provision_root(&old_wrap,otp));
    fj_hmac_snapshot_t snapshot={0}; memcpy(snapshot.root,new_root,32);
    uint8_t material[96]={6}; snapshot.entries[0].used=1;
    snapshot.entries[0].credential.credential_id[0]=9;
    assert(fj_hmac_credential_seal(&snapshot.entries[0].credential,new_root,material));
    fj_store_begin(); assert(fj_keys_set_timeout(222));
    uint32_t new_key_offset=FLASH_OFFSET_BYTES+(active_copy==0 ? 1u : 0u)*STORE_SLOT_SIZE;
    if (cut==1) cut_program_offset=FJ_HMAC_STAGE_OFFSET;
    if (cut==2) cut_program_offset=new_key_offset;
    if (cut==3) cut_program_offset=FJ_HMAC_STORE_OFFSET+FLASH_SECTOR_SIZE;
    uint8_t id[16]={7};
    bool ok=fj_restore_prepared(&snapshot,&new_wrap,otp,id);
    cut_program_offset=UINT32_MAX;
    assert(ok==(cut==0));
    if (!ok) {
        assert(fj_restore_boot_recover());
        fj_keys_init(); assert(fj_keys_ready()); assert(fj_hmac_store_init());
    }
    uint32_t timeout=0; assert(fj_keys_get_timeout(&timeout));
    assert(timeout==(cut==1 ? 111u : 222u));
    uint8_t opened[32]; assert(fj_hmac_store_open_root(FJ_HMAC_ROOT_OTP,otp,opened));
    assert(memcmp(opened,cut==1 ? old_root : new_root,32)==0);
    fj_hmac_credential_t got;
    assert(fj_hmac_store_get(snapshot.entries[0].credential.credential_id,&got)==(cut!=1));
}
static void device_restore(unsigned cut) {
    memset(test_flash,0xff,sizeof(test_flash));
    assert(fj_restore_boot_recover()); fj_keys_init(); assert(fj_keys_ready());
    assert(fj_hmac_store_init()); assert(fj_hmac_config_init());
    uint8_t old_root[32]={1},new_root[32]={2},salt[16]={3},nonce[12]={4},id[16]={5},key[32]={6};
    fj_hmac_root_record_t old_record;
    assert(fj_hmac_root_create(&old_record,FJ_HMAC_ROOT_DEVELOPMENT,old_root,NULL,salt,nonce));
    assert(fj_hmac_store_provision_root(&old_record,NULL));
    assert(fj_hmac_config_set(FJ_HMAC_PIN_BUTTON,FJ_HMAC_ROOT_DEVELOPMENT,NULL));
    static fj_backup_payload_t source,decoded;
    static fj_hmac_snapshot_t snapshot;
    static uint8_t blob[FJ_COMBINED_PASSWORD_SIZE],workspace[FJ_COMBINED_BACKUP_PAYLOAD];
    memset(&source,0,sizeof(source)); memset(&snapshot,0,sizeof(snapshot));
    assert(fj_keys_backup_fill(&source)); source.master[0]=42;
    source.ctap2[0].in_use=true; source.ctap2[0].credential_id[0]=10;
    memcpy(snapshot.root,new_root,32); snapshot.entries[0].used=1;
    snapshot.entries[0].credential.credential_id[0]=11;
    uint8_t material[96]={12};
    assert(fj_hmac_credential_seal(&snapshot.entries[0].credential,new_root,material));
    static fj_combined_password_job_t password_job;
    const uint8_t password[]="test-device-backup";
    fj_combined_job_init(&password_job);
    assert(fj_combined_job_seal(&password_job,&source,&snapshot,password,sizeof(password)-1,
                                salt,nonce,blob,sizeof(blob),workspace,sizeof(workspace)));
    while (fj_combined_job_step(&password_job)) {}
    assert(password_job.status==FJ_COMBINED_JOB_OK);
    fj_kdf_t kdf;
    assert(fj_kdf_begin(&kdf,password,sizeof(password)-1,salt,sizeof(salt),FJ_PBKDF2_ITERATIONS));
    while (kdf.running) fj_kdf_step(&kdf);
    assert(fj_kdf_result(&kdf,key));
    uint8_t wrong_key[32]; memcpy(wrong_key,key,32); wrong_key[0]^=1;
    assert(!fj_combined_device_restore_prepare(blob,sizeof(blob),wrong_key,&decoded));
    assert(fj_combined_device_restore_prepare(blob,sizeof(blob),key,&decoded));
    fj_restore_wraps_t wraps={0}; wraps.pass_hash[0]=13; wraps.puk_hash[0]=14;
    if (cut==1) cut_program_offset=FJ_HMAC_STAGE_OFFSET;
    if (cut==2) cut_program_offset=FLASH_OFFSET_BYTES+(active_copy==0 ? 1u : 0u)*STORE_SLOT_SIZE;
    bool ok=fj_combined_device_restore_commit(&decoded,&wraps,salt,nonce,id);
    cut_program_offset=UINT32_MAX;
    assert(ok==(cut==0));
    if (!ok) { assert(fj_restore_boot_recover()); fj_keys_init(); assert(fj_hmac_store_init()); }
    uint8_t root[32]; assert(fj_hmac_store_open_root(FJ_HMAC_ROOT_DEVELOPMENT,NULL,root));
    assert(!memcmp(root,cut==1 ? old_root : new_root,32));
    assert(fj_keys_passphrase_configured()==(cut!=1));
    fj_hmac_credential_t cred;
    assert(fj_hmac_store_get(snapshot.entries[0].credential.credential_id,&cred)==(cut!=1));
}
static void bundle_restore(unsigned cut) {
    memset(test_flash,0xff,sizeof(test_flash));
    assert(fj_restore_boot_recover()); fj_keys_init(); assert(fj_keys_ready());
    assert(fj_keys_set_timeout(111)); assert(fj_hmac_store_init());
    static fj_backup_payload_t keys;
    memset(&keys,0,sizeof(keys)); assert(fj_keys_backup_fill(&keys));
    memset(keys.master,0x39,sizeof(keys.master));
    keys.ctap2[0].in_use=true; keys.ctap2[0].credential_id[0]=0x75;
    fj_hmac_snapshot_t snapshot={0}; snapshot.root[0]=0x62;
    uint8_t material[96]={0x44}, opened[96];
    snapshot.entries[0].used=1; snapshot.entries[0].credential.credential_id[0]=0x57;
    assert(fj_hmac_credential_seal(&snapshot.entries[0].credential,snapshot.root,material));
    fj_restore_wraps_t wraps={0}; wraps.pass_hash[0]=1; wraps.pass_wrap_key[0]=2;
    wraps.puk_hash[0]=3; wraps.puk_wrap_key[0]=4;
    wraps.pass_salt[0]=5; wraps.pass_wrap_salt[0]=6;
    wraps.puk_salt[0]=7; wraps.puk_wrap_salt[0]=8;
    uint8_t otp[32]={9}, salt[16]={10}, nonce[12]={11}, id[16]={12};
    static fj_backup_payload_t decoded_keys;
    static fj_hmac_snapshot_t decoded_hmac;
    static uint8_t bundle[FJ_COMBINED_BACKUP_SIZE], workspace[FJ_COMBINED_BACKUP_PAYLOAD];
    uint8_t backup_key[32]={13}, backup_nonce[12]={14};
    if (cut==0) {
        static uint8_t password_blob[FJ_COMBINED_PASSWORD_SIZE];
        static fj_combined_password_job_t job;
        const uint8_t password[]="test-backup-password";
        uint8_t backup_salt[16]={15};
        fj_combined_job_init(&job);
        assert(fj_combined_job_seal(&job,&keys,&snapshot,password,sizeof(password)-1,backup_salt,
                                    backup_nonce,password_blob,sizeof(password_blob),workspace,sizeof(workspace)));
        while (fj_combined_job_step(&job)) {}
        assert(job.status==FJ_COMBINED_JOB_OK);
        fj_combined_job_init(&job);
        assert(fj_combined_job_open(&job,password_blob,sizeof(password_blob),password,sizeof(password)-1,
                                    &decoded_keys,&decoded_hmac,workspace,sizeof(workspace)));
        while (fj_combined_job_step(&job)) {}
        assert(job.status==FJ_COMBINED_JOB_OK);
    } else {
        assert(fj_combined_backup_seal(&keys,&snapshot,backup_key,backup_nonce,bundle,sizeof(bundle),workspace,sizeof(workspace)));
        assert(fj_combined_backup_open(bundle,sizeof(bundle),backup_key,&decoded_keys,&decoded_hmac,workspace,sizeof(workspace)));
    }
    /* Without a compatible boot configuration restore must not start. */
    assert(!fj_restore_bundle(&decoded_keys,&decoded_hmac,&wraps,FJ_HMAC_ROOT_OTP,otp,salt,nonce,id));
    uint8_t old_root[32]={0x23};
    fj_hmac_root_record_t old_record;
    assert(fj_hmac_root_create(&old_record,FJ_HMAC_ROOT_OTP,old_root,otp,salt,nonce));
    assert(fj_hmac_store_provision_root(&old_record,otp));
    assert(fj_hmac_config_init());
    assert(fj_hmac_config_set(FJ_HMAC_PIN_BUTTON,FJ_HMAC_ROOT_OTP,otp));
    assert(!fj_restore_bundle(&decoded_keys,&decoded_hmac,&wraps,FJ_HMAC_ROOT_DEVELOPMENT,NULL,salt,nonce,id));
    uint8_t wrong_otp[32]={0x7f};
    assert(!fj_restore_bundle(&decoded_keys,&decoded_hmac,&wraps,FJ_HMAC_ROOT_OTP,wrong_otp,salt,nonce,id));
    memcpy(decoded_keys.ctap2[0].credential_id,
           decoded_hmac.entries[0].credential.credential_id,FJ_CRED_ID_LEN);
    assert(!fj_restore_bundle(&decoded_keys,&decoded_hmac,&wraps,FJ_HMAC_ROOT_OTP,otp,salt,nonce,id));
    assert(!fj_keys_passphrase_configured());
    decoded_keys.ctap2[0].credential_id[0]=0x75;
    fj_store_begin(); assert(fj_keys_set_timeout(333));
    assert(!fj_restore_bundle(&decoded_keys,&decoded_hmac,&wraps,FJ_HMAC_ROOT_OTP,otp,salt,nonce,id));
    assert(store_tx && store.timeout_sec==333); fj_store_abort();
    if (cut==1) cut_program_offset=FJ_HMAC_STAGE_OFFSET;
    if (cut==2) cut_program_offset=FLASH_OFFSET_BYTES+(active_copy==0 ? 1u : 0u)*STORE_SLOT_SIZE;
    bool ok=fj_restore_bundle(&decoded_keys,&decoded_hmac,&wraps,FJ_HMAC_ROOT_OTP,otp,salt,nonce,id);
    cut_program_offset=UINT32_MAX; assert(ok==(cut==0));
    if (!ok) { assert(fj_restore_boot_recover()); fj_keys_init(); assert(fj_hmac_store_init()); }
    uint8_t hash[32], saved_salt[16], enc[32];
    if (cut==1) {
        assert(!fj_keys_passphrase_configured());
        assert(fj_hmac_store_open_root(FJ_HMAC_ROOT_OTP,otp,hash));
        assert(memcmp(hash,old_root,sizeof(old_root))==0);
    } else {
        assert(fj_keys_passphrase_configured());
        fj_keys_get_passphrase(hash,saved_salt);
        assert(memcmp(hash,wraps.pass_hash,32)==0 && memcmp(saved_salt,wraps.pass_salt,16)==0);
        assert(fj_keys_get_master_pin_wrap(enc,saved_salt));
        for (unsigned i=0;i<32;i++) assert((uint8_t)(enc[i]^wraps.pass_wrap_key[i])==keys.master[i]);
        assert(fj_keys_get_master_puk_wrap(enc,saved_salt));
        for (unsigned i=0;i<32;i++) assert((uint8_t)(enc[i]^wraps.puk_wrap_key[i])==keys.master[i]);
        assert(fj_hmac_store_open_root(FJ_HMAC_ROOT_OTP,otp,hash));
        fj_hmac_credential_t cred;
        assert(fj_hmac_store_get(snapshot.entries[0].credential.credential_id,&cred));
        assert(fj_hmac_credential_open(&cred,hash,opened));
        assert(memcmp(opened,material,sizeof(material))==0);
        assert(store.ctap2[0].credential_id[0]==0x75);
    }
}
int main(void) {
    for (unsigned old=0;old<2;old++)
        for (unsigned cut=0;cut<4;cut++) exercise(old,cut&1,cut&2);
    boot_recovery();
    for (unsigned cut=0;cut<4;cut++) prepared_restore(cut);
    for (unsigned cut=0;cut<3;cut++) bundle_restore(cut);
    for (unsigned cut=0;cut<3;cut++) device_restore(cut);
    puts("two-store activation, commit gating and interrupted writes: ok");
    return 0;
}
