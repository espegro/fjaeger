#define main hmac_assertion_tests_main
#include "test_hmac_assertion.c"
#undef main
#include "u2f.h"
#include "hmac_runtime.h"

uint32_t test_now;
static bool button,waiting;
static fj_hmac_policy_t policy;
uint32_t fj_state_session_epoch(void) { return 0; }
bool fj_boot_button_pressed(void) { return button; }
bool fj_keys_presence_button(void) { return false; }
unsigned fj_keys_active_profile(void) { return 0; }
void fj_led_set_presence_waiting(bool b) { waiting=b; }
bool tud_mounted(void) { return true; }
bool tud_hid_ready(void) { return false; }
bool tud_hid_n_report(uint8_t i,uint8_t id,const void *d,uint16_t n) { (void)i;(void)id;(void)d;(void)n;return true; }
bool fj_hmac_runtime_enabled(void) { return true; }
const fj_hmac_policy_t *fj_hmac_runtime_policy(void) { return &policy; }
bool fj_hmac_runtime_root_mode(fj_hmac_root_mode_t *m) { *m=FJ_HMAC_ROOT_DEVELOPMENT; return true; }
bool fj_ctap2_normal_id_exists(void *ctx,const uint8_t id[16]) { (void)ctx;(void)id;return false; }
size_t fj_ctap2_dispatch(const uint8_t *m,size_t n,uint8_t *o,size_t c) { (void)m;(void)n;assert(c);o[0]=0x11;return 1; }

static void send_request(const uint8_t *msg,size_t len) {
    uint8_t f[64]={0}; f[3]=1; f[4]=0x90; f[5]=(uint8_t)(len>>8); f[6]=(uint8_t)len;
    size_t first=len<57 ? len : 57; memcpy(f+7,msg,first); fj_u2f_hid_rx(f,64);
    size_t pos=first; uint8_t seq=0;
    while(pos<len) { memset(f,0,sizeof(f)); f[3]=1; f[4]=seq++;
        size_t take=len-pos<59 ? len-pos : 59; memcpy(f+5,msg+pos,take);
        fj_u2f_hid_rx(f,64); pos+=take; }
}
static void tick(unsigned ms) { test_now+=ms; fj_u2f_task(); }
static void press(void) { tick(31); button=true; tick(1); tick(31); button=false; tick(1); tick(31); }
static size_t response(uint8_t *out,size_t cap) {
    uint8_t f[64]; size_t pos=0,len=0; bool started=false;
    while(fj_u2f_pop_report(f)) {
        if (f[4]==0x90) { len=((size_t)f[5]<<8)|f[6]; assert(len<=cap); size_t n=len<57?len:57; memcpy(out,f+7,n); pos=n; started=true; }
        else if (started && !(f[4]&0x80)) { size_t n=len-pos<59?len-pos:59; memcpy(out+pos,f+5,n); pos+=n; }
    }
    assert(started && pos==len); return len;
}
int main(void) {
    memset(test_flash,0xff,sizeof(test_flash)); assert(fj_hmac_store_init());
    uint8_t root[32]={1},salt[16]={2},nonce[12]={3}; fj_hmac_root_record_t record;
    assert(fj_hmac_root_create(&record,FJ_HMAC_ROOT_DEVELOPMENT,root,NULL,salt,nonce));
    assert(fj_hmac_store_provision_root(&record,NULL));
    assert(fj_hmac_policy_init(&policy,FJ_HMAC_PIN_BUTTON,false,0));
    memset(agreement,0x37,sizeof(agreement)); pin_ok=true; test_state=FJ_STATE_UNLOCKED; fj_u2f_init();
    uint8_t req[512],out[512],client[32]={0},param[16]={0x31},user[1]={1},id[16]; fj_cbor_writer w;
    req[0]=1; fj_cbor_writer_init(&w,req+1,sizeof(req)-1); fj_cbor_map(&w,7);
    fj_cbor_uint(&w,1);fj_cbor_bstr(&w,client,32);
    fj_cbor_uint(&w,2);fj_cbor_map(&w,1);fj_cbor_tstr(&w,"id");fj_cbor_tstr(&w,"example.org");
    fj_cbor_uint(&w,3);fj_cbor_map(&w,1);fj_cbor_tstr(&w,"id");fj_cbor_bstr(&w,user,1);
    fj_cbor_uint(&w,4);fj_cbor_array(&w,1);fj_cbor_map(&w,2);fj_cbor_tstr(&w,"alg");fj_cbor_neg(&w,6);fj_cbor_tstr(&w,"type");fj_cbor_tstr(&w,"public-key");
    fj_cbor_uint(&w,6);fj_cbor_map(&w,1);fj_cbor_tstr(&w,"hmac-secret");fj_cbor_bool(&w,true);
    fj_cbor_uint(&w,8);fj_cbor_bstr(&w,param,16);fj_cbor_uint(&w,9);fj_cbor_uint(&w,1);
    assert(fj_cbor_ok(&w)); send_request(req,w.len+1); assert(waiting); press(); assert(!waiting);
    size_t n=response(out,sizeof(out)); assert(n>1 && out[0]==0);
    fj_cbor_reader r; fj_cbor_item item; uint8_t auth[200]; size_t alen;
    fj_cbor_reader_init(&r,out+1,n-1); assert(fj_cbor_next(&r,&item));
    assert(fj_cbor_next(&r,&item) && item.val==1); assert(fj_cbor_next(&r,&item) && fj_cbor_skip(&r,&item));
    assert(fj_cbor_next(&r,&item) && item.val==2); assert(fj_cbor_next(&r,&item) && fj_cbor_read_bytes(&r,&item,auth,sizeof(auth),&alen));
    assert(alen>71 && auth[32]==0xc5); memcpy(id,auth+55,16);
    uint8_t enc[32]={7},mac[32],iv[16]={0},coord[32]={1};
    assert(fj_aes_cbc(agreement,iv,enc,32,true)); assert(fj_hmac_sha256(agreement,32,enc,32,mac));
    req[0]=2;fj_cbor_writer_init(&w,req+1,sizeof(req)-1);fj_cbor_map(&w,6);
    fj_cbor_uint(&w,1);fj_cbor_tstr(&w,"example.org"); fj_cbor_uint(&w,2);fj_cbor_bstr(&w,client,32);
    fj_cbor_uint(&w,3);fj_cbor_array(&w,1);fj_cbor_map(&w,2);fj_cbor_tstr(&w,"id");fj_cbor_bstr(&w,id,16);fj_cbor_tstr(&w,"type");fj_cbor_tstr(&w,"public-key");
    fj_cbor_uint(&w,4);fj_cbor_map(&w,1);fj_cbor_tstr(&w,"hmac-secret");fj_cbor_map(&w,4);
    fj_cbor_uint(&w,1);fj_cbor_map(&w,5);fj_cbor_uint(&w,1);fj_cbor_uint(&w,2);fj_cbor_uint(&w,3);fj_cbor_neg(&w,24);fj_cbor_neg(&w,0);fj_cbor_uint(&w,1);fj_cbor_neg(&w,1);fj_cbor_bstr(&w,coord,32);fj_cbor_neg(&w,2);fj_cbor_bstr(&w,coord,32);
    fj_cbor_uint(&w,2);fj_cbor_bstr(&w,enc,32);fj_cbor_uint(&w,3);fj_cbor_bstr(&w,mac,16);fj_cbor_uint(&w,4);fj_cbor_uint(&w,1);
    fj_cbor_uint(&w,6);fj_cbor_bstr(&w,param,16);fj_cbor_uint(&w,7);fj_cbor_uint(&w,1);
    assert(fj_cbor_ok(&w));test_state=FJ_STATE_LOCKED;send_request(req,w.len+1);assert(waiting);press();
    n=response(out,sizeof(out));assert(n>1 && out[0]==0 && test_state==FJ_STATE_LOCKED);
    fj_cbor_reader_init(&r,out+1,n-1);assert(fj_cbor_next(&r,&item));
    assert(fj_cbor_next(&r,&item) && item.val==1);assert(fj_cbor_next(&r,&item) && fj_cbor_skip(&r,&item));
    assert(fj_cbor_next(&r,&item) && item.val==2);assert(fj_cbor_next(&r,&item) && fj_cbor_read_bytes(&r,&item,auth,sizeof(auth),&alen));
    assert(alen>37 && auth[32]==0x85);
    fj_hmac_assertion_result_t result={0}; memcpy(result.auth_data,auth,alen); result.auth_data_len=alen;
    assert(fj_cbor_next(&r,&item) && item.val==3);
    assert(fj_cbor_next(&r,&item) && fj_cbor_read_bytes(&r,&item,result.signature,sizeof(result.signature),&result.signature_len));
    fj_hmac_credential_t credential; uint8_t material[96],plain_salt[32]={7};
    assert(fj_hmac_store_get(id,&credential)); assert(fj_hmac_credential_open(&credential,root,material));
    fj_hmac_assertion_request_t signed_request={0}; memcpy(signed_request.client_data_hash,client,32);
    verify_signature(&signed_request,&result,credential.public_key);
    verify_output(&signed_request,&result,material+32,plain_salt);
    /* systemd asks for a no-UP assertion without extensions as preflight. */
    req[0]=2;fj_cbor_writer_init(&w,req+1,sizeof(req)-1);fj_cbor_map(&w,4);
    fj_cbor_uint(&w,1);fj_cbor_tstr(&w,"example.org");
    fj_cbor_uint(&w,2);fj_cbor_bstr(&w,client,32);
    fj_cbor_uint(&w,3);fj_cbor_array(&w,1);fj_cbor_map(&w,2);
    fj_cbor_tstr(&w,"id");fj_cbor_bstr(&w,id,16);fj_cbor_tstr(&w,"type");fj_cbor_tstr(&w,"public-key");
    fj_cbor_uint(&w,5);fj_cbor_map(&w,1);fj_cbor_tstr(&w,"up");fj_cbor_bool(&w,false);
    assert(fj_cbor_ok(&w)); size_t preflight_len=w.len+1;
    assert(fj_hmac_policy_init(&policy,FJ_HMAC_ARMED,false,test_now));
    send_request(req,preflight_len); n=response(out,sizeof(out)); assert(n==1 && out[0]==0x27);
    assert(fj_hmac_policy_init(&policy,FJ_HMAC_AUTO,false,test_now));
    send_request(req,preflight_len); n=response(out,sizeof(out)); assert(n>1 && out[0]==0 && !waiting);
    fj_cbor_reader_init(&r,out+1,n-1);assert(fj_cbor_next(&r,&item));
    assert(fj_cbor_next(&r,&item) && item.val==1);assert(fj_cbor_next(&r,&item) && fj_cbor_skip(&r,&item));
    assert(fj_cbor_next(&r,&item) && item.val==2);
    assert(fj_cbor_next(&r,&item) && fj_cbor_read_bytes(&r,&item,result.auth_data,sizeof(result.auth_data),&result.auth_data_len));
    assert(result.auth_data_len==37 && result.auth_data[32]==0);
    assert(fj_cbor_next(&r,&item) && item.val==3);
    assert(fj_cbor_next(&r,&item) && fj_cbor_read_bytes(&r,&item,result.signature,sizeof(result.signature),&result.signature_len));
    verify_signature(&signed_request,&result,credential.public_key);
    id[0]^=1;
    fj_cbor_writer_init(&w,req+1,sizeof(req)-1);fj_cbor_map(&w,4);
    fj_cbor_uint(&w,1);fj_cbor_tstr(&w,"example.org");fj_cbor_uint(&w,2);fj_cbor_bstr(&w,client,32);
    fj_cbor_uint(&w,3);fj_cbor_array(&w,1);fj_cbor_map(&w,2);fj_cbor_tstr(&w,"id");fj_cbor_bstr(&w,id,16);fj_cbor_tstr(&w,"type");fj_cbor_tstr(&w,"public-key");
    fj_cbor_uint(&w,5);fj_cbor_map(&w,1);fj_cbor_tstr(&w,"up");fj_cbor_bool(&w,false);
    send_request(req,w.len+1);n=response(out,sizeof(out));assert(n==1 && out[0]==0x2e);
    assert(fj_hmac_store_remove(credential.credential_id));
    req[0]=1;fj_cbor_writer_init(&w,req+1,sizeof(req)-1);fj_cbor_map(&w,5);
    fj_cbor_uint(&w,1);fj_cbor_bstr(&w,client,32);
    fj_cbor_uint(&w,2);fj_cbor_map(&w,1);fj_cbor_tstr(&w,"id");fj_cbor_tstr(&w,"example.org");
    fj_cbor_uint(&w,3);fj_cbor_map(&w,1);fj_cbor_tstr(&w,"id");fj_cbor_bstr(&w,user,1);
    fj_cbor_uint(&w,4);fj_cbor_array(&w,1);fj_cbor_map(&w,2);fj_cbor_tstr(&w,"alg");fj_cbor_neg(&w,6);fj_cbor_tstr(&w,"type");fj_cbor_tstr(&w,"public-key");
    fj_cbor_uint(&w,6);fj_cbor_map(&w,1);fj_cbor_tstr(&w,"hmac-secret");fj_cbor_bool(&w,true);
    assert(fj_cbor_ok(&w));send_request(req,w.len+1);n=response(out,sizeof(out));assert(n==1 && out[0]==0x27);
    test_state=FJ_STATE_UNLOCKED;send_request(req,w.len+1);assert(waiting);press();
    n=response(out,sizeof(out));assert(n>1 && out[0]==0);
    fj_cbor_reader_init(&r,out+1,n-1);assert(fj_cbor_next(&r,&item));
    assert(fj_cbor_next(&r,&item) && item.val==1);assert(fj_cbor_next(&r,&item) && fj_cbor_skip(&r,&item));
    assert(fj_cbor_next(&r,&item) && item.val==2);
    assert(fj_cbor_next(&r,&item) && fj_cbor_read_bytes(&r,&item,auth,sizeof(auth),&alen));
    assert(auth[32]==0xc1); /* actual UP, no unverified UV */
    puts("hmac HID enrollment and locked assertion: ok");return 0;
}
