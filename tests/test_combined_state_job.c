#define main restore_activation_tests_main
#include "test_restore_activation.c"
#undef main
#include "state.h"
#include "job.h"
#include "pico/time.h"
#include <setjmp.h>

static uint8_t backup_file[FJ_BLOB_MAX];
static size_t backup_len;
static unsigned lock_calls,token_resets,cache_flushes;
static jmp_buf halt_jump;
_Noreturn void __wrap_fj_factory_wipe_halt(void) { longjmp(halt_jump,1); }
absolute_time_t get_absolute_time(void) { return 1000000000; }
int64_t absolute_time_diff_us(absolute_time_t a,absolute_time_t b) { return b-a; }
bool fj_msc_is_ready(void) { return true; }
void fj_msc_lock(void) { lock_calls++; }
void fj_msc_force_lock(void) {}
bool fj_msc_backup_write(const uint8_t *data,size_t len) {
    if (len>sizeof(backup_file)) return false;
    memcpy(backup_file,data,len); backup_len=len; return true;
}
bool fj_msc_backup_read(uint8_t *out,size_t cap,size_t *len) {
    if (!backup_len || cap<backup_len) return false;
    memcpy(out,backup_file,backup_len); *len=backup_len; return true;
}
void fj_led_pin_lock(void) {}
void fj_led_pin_unlock(void) {}
void fj_pin_reset_token(void) { token_resets++; }
void fj_ctap2_invalidate_discovery(void) {}
void fj_ctap2_forget_profile(unsigned p) { (void)p; }
void fj_ctap2_forget_all(void) { cache_flushes++; }
void fj_ctap2_init(void) {}
bool fj_hmac_runtime_enabled(void) { return true; }
bool fj_hmac_runtime_init(const uint8_t *otp,bool pressed,uint32_t now) {
    (void)otp; (void)pressed; (void)now; return true;
}
void fj_hmac_runtime_forget(void) {}

int main(void) {
    memset(test_flash,0xff,sizeof(test_flash));
    assert(fj_restore_boot_recover()); fj_keys_init(); assert(fj_keys_ready());
    assert(fj_hmac_store_init()); assert(fj_hmac_config_init());
    uint8_t root[32]={1},salt[16]={2},nonce[12]={3},material[96]={4};
    fj_hmac_root_record_t record;
    assert(fj_hmac_root_create(&record,FJ_HMAC_ROOT_DEVELOPMENT,root,NULL,salt,nonce));
    assert(fj_hmac_store_provision_root(&record,NULL));
    assert(fj_hmac_config_set(FJ_HMAC_PIN_BUTTON,FJ_HMAC_ROOT_DEVELOPMENT,NULL));
    fj_hmac_credential_t cred={0}; cred.credential_id[0]=0x44;
    assert(fj_hmac_credential_seal(&cred,root,material));
    assert(fj_hmac_store_put(&cred));
    fj_state_init();
    assert(fj_state_set_passphrase("original-passphrase"));
    assert(fj_state_unlock("original-passphrase"));
    uint8_t old_master[32],restored_master[32]; assert(fj_state_cwk(old_master));
    assert(fj_state_backup_write("backup-password"));
    assert(backup_len==FJ_COMBINED_PASSWORD_SIZE && !memcmp(backup_file,"FJCP",4));
    assert(!fj_state_backup_restore("wrong-password","new-passphrase","new-recovery"));
    cut_program_offset=FJ_HMAC_STAGE_OFFSET;
    if (!setjmp(halt_jump)) {
        (void)fj_state_backup_restore("backup-password","new-passphrase","new-recovery");
        assert(!"interrupted restore must halt for recovery");
    }
    cut_program_offset=UINT32_MAX;
    assert(fj_restore_boot_recover()); fj_keys_init(); assert(fj_hmac_store_init());
    fj_state_init();
    assert(fj_state_unlock("original-passphrase"));
    assert(fj_state_backup_restore("backup-password","new-passphrase","new-recovery"));
    assert(fj_state_get()==FJ_STATE_LOCKED && lock_calls && token_resets && cache_flushes);
    assert(!fj_state_cwk(restored_master));
    assert(fj_state_unlock("new-passphrase"));
    assert(fj_state_cwk(restored_master) && !memcmp(old_master,restored_master,32));
    uint8_t restored_root[32],decoded[96]; fj_hmac_credential_t restored;
    assert(fj_hmac_store_open_root(FJ_HMAC_ROOT_DEVELOPMENT,NULL,restored_root));
    assert(fj_hmac_store_get(cred.credential_id,&restored));
    assert(fj_hmac_credential_open(&restored,restored_root,decoded));
    assert(!memcmp(material,decoded,sizeof(material)));
    cut_program_offset=FLASH_OFFSET_BYTES+(active_copy==0 ? 1u : 0u)*STORE_SLOT_SIZE;
    if (!setjmp(halt_jump)) {
        (void)fj_state_backup_restore("backup-password","final-passphrase","final-recovery");
        assert(!"interrupted committed restore must halt for recovery");
    }
    cut_program_offset=UINT32_MAX;
    assert(fj_restore_boot_recover()); fj_keys_init(); assert(fj_hmac_store_init());
    fj_state_init();
    assert(fj_state_unlock("final-passphrase"));
    assert(fj_state_cwk(restored_master) && !memcmp(old_master,restored_master,32));
    assert(fj_hmac_store_get(cred.credential_id,&restored));
    puts("combined state backup and restore with simulated flash: ok");
}
