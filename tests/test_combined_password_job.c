#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "combined_password_job.h"
#include "job.h"
#include "msc_disk.h"

_Static_assert(FJ_COMBINED_PASSWORD_SIZE<=FJ_BLOB_MAX,"combined backup fits job buffer");
_Static_assert(FJ_COMBINED_PASSWORD_SIZE<=FJ_MSC_BACKUP_MAX,"combined backup fits MSC file");
void fj_random(void *p,size_t n) { memset(p,0x42,n); }
static fj_backup_payload_t keys, recovered_keys;
static fj_hmac_snapshot_t hmac, recovered_hmac;
static uint8_t blob[FJ_COMBINED_PASSWORD_SIZE], workspace[FJ_COMBINED_BACKUP_PAYLOAD];
static fj_combined_password_job_t job;
static void zeroed(const void *p,size_t n) {
    const uint8_t *b=p; for(size_t i=0;i<n;i++) assert(b[i]==0);
}
static void run(void) {
    unsigned calls=0;
    while (job.status==FJ_COMBINED_JOB_RUNNING) {
        uint32_t before=job.kdf.i;
        bool more=fj_combined_job_step(&job);
        if (more) assert(job.kdf.i-before<=FJ_COMBINED_KDF_STEPS_PER_TICK);
        assert(++calls<1000);
    }
    assert(calls>1);
    zeroed(&job.kdf,sizeof(job.kdf)); zeroed(workspace,sizeof(workspace));
}
int main(void) {
    const uint8_t password[]="example password", bad[]="incorrect password";
    uint8_t salt[16]={1},nonce[12]={2},material[96]={3},opened[96];
    keys.active_profile_valid=1; keys.profiles[0].in_use=true;
    memcpy(keys.profiles[0].name,"Default",8); keys.master[0]=0x91;
    hmac.root[0]=0x83; hmac.entries[0].used=1;
    hmac.entries[0].credential.credential_id[0]=7;
    assert(fj_hmac_credential_seal(&hmac.entries[0].credential,hmac.root,material));
    fj_combined_job_init(&job);
    assert(fj_combined_job_seal(&job,&keys,&hmac,password,sizeof(password)-1,salt,nonce,blob,sizeof(blob),workspace,sizeof(workspace)));
    assert(!fj_combined_job_seal(&job,&keys,&hmac,password,sizeof(password)-1,salt,nonce,blob,sizeof(blob),workspace,sizeof(workspace)));
    assert(fj_combined_job_step(&job)); fj_combined_job_cancel(&job);
    assert(job.status==FJ_COMBINED_JOB_CANCELLED);
    zeroed(&job.kdf,sizeof(job.kdf)); zeroed(blob,sizeof(blob)); zeroed(workspace,sizeof(workspace));
    fj_combined_job_init(&job);
    assert(fj_combined_job_seal(&job,&keys,&hmac,password,sizeof(password)-1,salt,nonce,blob,sizeof(blob),workspace,sizeof(workspace)));
    run(); assert(job.status==FJ_COMBINED_JOB_OK);
    fj_combined_job_init(&job);
    assert(fj_combined_job_open(&job,blob,sizeof(blob),password,sizeof(password)-1,&recovered_keys,&recovered_hmac,workspace,sizeof(workspace)));
    run(); assert(job.status==FJ_COMBINED_JOB_OK);
    assert(memcmp(&keys,&recovered_keys,sizeof(keys))==0);
    assert(fj_hmac_credential_open(&recovered_hmac.entries[0].credential,recovered_hmac.root,opened));
    assert(memcmp(opened,material,sizeof(material))==0);
    fj_combined_job_init(&job);
    assert(fj_combined_job_open(&job,blob,sizeof(blob),bad,sizeof(bad)-1,&recovered_keys,&recovered_hmac,workspace,sizeof(workspace)));
    run(); assert(job.status==FJ_COMBINED_JOB_FAILED);
    zeroed(&recovered_keys,sizeof(recovered_keys)); zeroed(&recovered_hmac,sizeof(recovered_hmac));
    fj_combined_job_init(&job);
    assert(fj_combined_job_open(&job,blob,sizeof(blob),password,sizeof(password)-1,&recovered_keys,&recovered_hmac,workspace,sizeof(workspace)));
    assert(fj_combined_job_step(&job)); fj_combined_job_cancel(&job);
    assert(job.status==FJ_COMBINED_JOB_CANCELLED);
    zeroed(&recovered_keys,sizeof(recovered_keys)); zeroed(&recovered_hmac,sizeof(recovered_hmac));
    zeroed(&job.kdf,sizeof(job.kdf));
    fj_combined_job_init(&job); blob[5]=1;
    memset(&recovered_keys,0x5a,sizeof(recovered_keys));
    memset(&recovered_hmac,0x5a,sizeof(recovered_hmac));
    assert(!fj_combined_job_open(&job,blob,sizeof(blob),password,sizeof(password)-1,&recovered_keys,&recovered_hmac,workspace,sizeof(workspace)));
    zeroed(&recovered_keys,sizeof(recovered_keys)); zeroed(&recovered_hmac,sizeof(recovered_hmac));
    puts("cooperative combined password backup and cancellation: ok");
}
