#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <mbedtls/ecdsa.h>
#include "hardware/flash.h"
#include "crypto.h"
#include "hmac_assertion.h"
#include "hmac_store.h"
#include "hmac_enroll.h"
#include "hmac_ctap.h"
#include "state.h"
#include "cbor.h"

_Alignas(4) uint8_t test_flash[PICO_FLASH_SIZE_BYTES];
static bool pin_ok;
static fj_state_t test_state=FJ_STATE_LOCKED;
static bool normal_present, normal_collision_all;
static bool normal_id(void *ctx,const uint8_t id[16]) {
    (void)ctx;
    return normal_collision_all || (normal_present && id[0]==0x99);
}
static uint8_t agreement[32];
fj_state_t fj_state_get(void) { return test_state; }
void fj_random(void *p,size_t n) { memset(p,0x42,n); }
void flash_range_erase(uint32_t offset,size_t n) { assert(offset+n<=sizeof(test_flash)); memset(test_flash+offset,0xff,n); }
void flash_range_program(uint32_t offset,const uint8_t *p,size_t n) { assert(offset+n<=sizeof(test_flash)); memcpy(test_flash+offset,p,n); }
bool fj_pin_verify_user_auth(const uint8_t *message,size_t len,const uint8_t param[16]) {
    return pin_ok && message && len==32 && param[0]==0x31;
}
bool fj_pin_shared_secret(const uint8_t pub[65],uint8_t out[32]) {
    if (pub[0]!=4) return false;
    memcpy(out,agreement,32); return true;
}
static void verify_signature(const fj_hmac_assertion_request_t *r,
                             const fj_hmac_assertion_result_t *result,const uint8_t pub[65]) {
    uint8_t data[192],digest[32];
    memcpy(data,result->auth_data,result->auth_data_len);
    memcpy(data+result->auth_data_len,r->client_data_hash,32);
    fj_sha256(data,result->auth_data_len+32,digest);
    mbedtls_ecdsa_context ctx; mbedtls_ecdsa_init(&ctx);
    assert(mbedtls_ecp_group_load(&ctx.MBEDTLS_PRIVATE(grp),MBEDTLS_ECP_DP_SECP256R1)==0);
    assert(mbedtls_ecp_point_read_binary(&ctx.MBEDTLS_PRIVATE(grp),&ctx.MBEDTLS_PRIVATE(Q),pub,65)==0);
    assert(mbedtls_ecdsa_read_signature(&ctx,digest,32,result->signature,result->signature_len)==0);
    mbedtls_ecdsa_free(&ctx);
}
static void verify_output(const fj_hmac_assertion_request_t *r,
                          const fj_hmac_assertion_result_t *result,const uint8_t random[32],
                          const uint8_t salt[32]) {
    fj_cbor_reader reader; fj_cbor_item item; size_t n=0;
    fj_cbor_reader_init(&reader,result->auth_data+37,result->auth_data_len-37);
    assert(fj_cbor_next(&reader,&item) && item.type==FJ_CBOR_MAP && item.val==1);
    assert(fj_cbor_next(&reader,&item) && item.type==FJ_CBOR_TSTR);
    uint8_t name[16]; assert(fj_cbor_read_bytes(&reader,&item,name,sizeof(name),&n));
    assert(n==11 && memcmp(name,"hmac-secret",11)==0);
    assert(fj_cbor_next(&reader,&item) && item.type==FJ_CBOR_BSTR);
    uint8_t encrypted[64],expected[32],iv[16]={0};
    assert(fj_cbor_read_bytes(&reader,&item,encrypted,sizeof(encrypted),&n) && n==32);
    assert(fj_aes_cbc(agreement,iv,encrypted,n,false));
    assert(fj_hmac_sha256(random,32,salt,32,expected));
    assert(memcmp(encrypted,expected,32)==0);
    (void)r;
}
static void ctap_roundtrip(const fj_hmac_root_record_t *wrapped,const uint8_t otp[32],
                           const uint8_t salt[32]) {
    assert(fj_hmac_store_wipe()); assert(fj_hmac_store_provision_root(wrapped,otp));
    fj_hmac_policy_t policy; assert(fj_hmac_policy_init(&policy,FJ_HMAC_PIN_BUTTON,false,0));
    fj_hmac_ctap_context_t ctx={.policy=&policy,.mode=FJ_HMAC_ROOT_OTP,.otp=otp,
                                .user_present=true,.normal_id_exists=normal_id};
    uint8_t req[512],out[512],client[32]={0},param[16]={0x31},userid[1]={1},id[16];
    fj_cbor_writer w; req[0]=1; fj_cbor_writer_init(&w,req+1,sizeof(req)-1);
    fj_cbor_map(&w,8);
    fj_cbor_uint(&w,1); fj_cbor_bstr(&w,client,32);
    fj_cbor_uint(&w,2); fj_cbor_map(&w,1); fj_cbor_tstr(&w,"id"); fj_cbor_tstr(&w,"example.org");
    fj_cbor_uint(&w,3); fj_cbor_map(&w,1); fj_cbor_tstr(&w,"id"); fj_cbor_bstr(&w,userid,1);
    fj_cbor_uint(&w,4); fj_cbor_array(&w,1); fj_cbor_map(&w,2);
    fj_cbor_tstr(&w,"alg"); fj_cbor_neg(&w,6); fj_cbor_tstr(&w,"type"); fj_cbor_tstr(&w,"public-key");
    uint8_t excluded[16]={0x99};
    fj_cbor_uint(&w,5); fj_cbor_array(&w,1); fj_cbor_map(&w,2);
    fj_cbor_tstr(&w,"id"); fj_cbor_bstr(&w,excluded,16);
    fj_cbor_tstr(&w,"type"); fj_cbor_tstr(&w,"public-key");
    fj_cbor_uint(&w,6); fj_cbor_map(&w,1); fj_cbor_tstr(&w,"hmac-secret"); fj_cbor_bool(&w,true);
    fj_cbor_uint(&w,8); fj_cbor_bstr(&w,param,16);
    fj_cbor_uint(&w,9); fj_cbor_uint(&w,1);
    assert(fj_cbor_ok(&w)); size_t req_len=w.len+1;
    assert(fj_hmac_ctap_classify(req,req_len)==FJ_HMAC_ROUTE_HMAC);
    test_state=FJ_STATE_UNLOCKED; pin_ok=true;
    assert(fj_hmac_ctap_dispatch(req,req_len,&ctx,out,16)==1 && out[0]!=0);
    ctx.user_present=false;
    assert(fj_hmac_ctap_dispatch(req,req_len,&ctx,out,sizeof(out))==1 && out[0]!=0);
    ctx.user_present=true;
    normal_present=true;
    assert(fj_hmac_ctap_dispatch(req,req_len,&ctx,out,sizeof(out))==1 && out[0]==0x19);
    normal_present=false; normal_collision_all=true;
    assert(fj_hmac_ctap_dispatch(req,req_len,&ctx,out,sizeof(out))==1 && out[0]!=0);
    normal_collision_all=false;
    size_t len=fj_hmac_ctap_dispatch(req,req_len,&ctx,out,sizeof(out));
    assert(len>1 && out[0]==0);
    fj_cbor_reader r; fj_cbor_item item; size_t n=0;
    fj_cbor_reader_init(&r,out+1,len-1);
    assert(fj_cbor_next(&r,&item) && item.type==FJ_CBOR_MAP && item.val==3);
    assert(fj_cbor_next(&r,&item) && item.val==1);
    assert(fj_cbor_next(&r,&item) && fj_cbor_skip(&r,&item));
    assert(fj_cbor_next(&r,&item) && item.val==2);
    uint8_t authdata[200];
    assert(fj_cbor_next(&r,&item) && fj_cbor_read_bytes(&r,&item,authdata,sizeof(authdata),&n));
    assert(n>71 && authdata[32]==0xc5); memcpy(id,authdata+55,16);
    fj_hmac_credential_t credential; assert(fj_hmac_store_get(id,&credential));
    uint8_t encrypted[32],auth[32],iv[16]={0},coord[32]={1};
    memcpy(encrypted,salt,32); assert(fj_aes_cbc(agreement,iv,encrypted,32,true));
    assert(fj_hmac_sha256(agreement,32,encrypted,32,auth));
    req[0]=2; fj_cbor_writer_init(&w,req+1,sizeof(req)-1); fj_cbor_map(&w,7);
    fj_cbor_uint(&w,1); fj_cbor_tstr(&w,"example.org");
    fj_cbor_uint(&w,2); fj_cbor_bstr(&w,client,32);
    fj_cbor_uint(&w,3); fj_cbor_array(&w,2); fj_cbor_map(&w,2);
    fj_cbor_tstr(&w,"id"); fj_cbor_bstr(&w,client,32);
    fj_cbor_tstr(&w,"type"); fj_cbor_tstr(&w,"public-key");
    fj_cbor_map(&w,2);
    fj_cbor_tstr(&w,"id"); fj_cbor_bstr(&w,id,16);
    fj_cbor_tstr(&w,"type"); fj_cbor_tstr(&w,"public-key");
    fj_cbor_uint(&w,4); fj_cbor_map(&w,1); fj_cbor_tstr(&w,"hmac-secret"); fj_cbor_map(&w,4);
    fj_cbor_uint(&w,1); fj_cbor_map(&w,5);
    fj_cbor_uint(&w,1); fj_cbor_uint(&w,2); fj_cbor_uint(&w,3); fj_cbor_neg(&w,24);
    fj_cbor_neg(&w,0); fj_cbor_uint(&w,1);
    fj_cbor_neg(&w,1); fj_cbor_bstr(&w,coord,32); fj_cbor_neg(&w,2); fj_cbor_bstr(&w,coord,32);
    fj_cbor_uint(&w,2); fj_cbor_bstr(&w,encrypted,32);
    fj_cbor_uint(&w,3); fj_cbor_bstr(&w,auth,16);
    fj_cbor_uint(&w,4); fj_cbor_uint(&w,1);
    fj_cbor_uint(&w,5); fj_cbor_map(&w,2); fj_cbor_tstr(&w,"up"); fj_cbor_bool(&w,true);
    fj_cbor_tstr(&w,"uv"); fj_cbor_bool(&w,true);
    size_t without_pin_len=w.len+1;
    fj_cbor_uint(&w,6); fj_cbor_bstr(&w,param,16); fj_cbor_uint(&w,7); fj_cbor_uint(&w,1);
    assert(fj_cbor_ok(&w)); req_len=w.len+1; test_state=FJ_STATE_LOCKED;
    assert(fj_hmac_ctap_classify(req,req_len)==FJ_HMAC_ROUTE_HMAC);
    len=fj_hmac_ctap_dispatch(req,req_len,&ctx,out,sizeof(out)); assert(len>1 && out[0]==0);
    assert(fj_hmac_policy_init(&policy,FJ_HMAC_AUTO,false,0));
    req[1]=0xa5; /* Same request and uv=true, without PIN fields. */
    assert(fj_hmac_ctap_dispatch(req,without_pin_len,&ctx,out,sizeof(out))==1 && out[0]!=0);
    req[1]=0xa7;
    assert(fj_hmac_policy_init(&policy,FJ_HMAC_PIN_BUTTON,false,0));
    len=fj_hmac_ctap_dispatch(req,req_len,&ctx,out,sizeof(out)); assert(len>1 && out[0]==0);
    assert(test_state==FJ_STATE_LOCKED);
    fj_hmac_assertion_result_t assertion={0};
    fj_cbor_reader_init(&r,out+1,len-1);
    assert(fj_cbor_next(&r,&item) && item.type==FJ_CBOR_MAP && item.val==3);
    assert(fj_cbor_next(&r,&item) && item.val==1);
    assert(fj_cbor_next(&r,&item) && fj_cbor_skip(&r,&item));
    assert(fj_cbor_next(&r,&item) && item.val==2);
    assert(fj_cbor_next(&r,&item) && fj_cbor_read_bytes(&r,&item,assertion.auth_data,sizeof(assertion.auth_data),&assertion.auth_data_len));
    assert(fj_cbor_next(&r,&item) && item.val==3);
    assert(fj_cbor_next(&r,&item) && fj_cbor_read_bytes(&r,&item,assertion.signature,sizeof(assertion.signature),&assertion.signature_len));
    fj_hmac_assertion_request_t signed_request={0};
    memcpy(signed_request.client_data_hash,client,32);
    verify_signature(&signed_request,&assertion,credential.public_key);
    pin_ok=false; assert(fj_hmac_ctap_dispatch(req,req_len,&ctx,out,sizeof(out))==1 && out[0]!=0);
    pin_ok=true;
    for (size_t prefix=1;prefix<req_len;prefix++)
        { assert(fj_hmac_ctap_dispatch(req,prefix,&ctx,out,sizeof(out))==1 && out[0]!=0);
          assert(fj_hmac_ctap_classify(req,prefix)==FJ_HMAC_ROUTE_INVALID); }
    uint8_t normal[]={1,0xa0}, info[]={4};
    assert(fj_hmac_ctap_classify(normal,sizeof(normal))==FJ_HMAC_ROUTE_NORMAL);
    assert(fj_hmac_ctap_classify(info,sizeof(info))==FJ_HMAC_ROUTE_NORMAL);
    uint8_t duplicate[128]; duplicate[0]=1;
    fj_cbor_writer_init(&w,duplicate+1,sizeof(duplicate)-1);
    fj_cbor_map(&w,1); fj_cbor_uint(&w,6); fj_cbor_map(&w,2);
    fj_cbor_tstr(&w,"hmac-secret"); fj_cbor_bool(&w,false);
    fj_cbor_tstr(&w,"hmac-secret"); fj_cbor_bool(&w,true);
    assert(fj_cbor_ok(&w));
    assert(fj_hmac_ctap_classify(duplicate,w.len+1)==FJ_HMAC_ROUTE_INVALID);
}
int main(void) {
    memset(test_flash,0xff,sizeof(test_flash));
    uint8_t unknown_id[16]={0x77};
    assert(fj_hmac_store_id_exists(NULL,unknown_id)); /* unavailable fails closed */
    assert(fj_hmac_store_init());
    assert(!fj_hmac_store_id_exists(NULL,unknown_id));
    uint8_t root[32]={1},otp[32]={2},wrap_salt[16]={3},nonce[12]={4};
    fj_hmac_root_record_t wrapped;
    assert(fj_hmac_root_create(&wrapped,FJ_HMAC_ROOT_OTP,root,otp,wrap_salt,nonce));
    assert(fj_hmac_store_provision_root(&wrapped,otp));
    uint8_t material[96]={0}; material[31]=1;
    memset(material+32,0x25,32); memset(material+64,0x36,32);
    fj_hmac_credential_t credential={0}; credential.credential_id[0]=7;
    credential.rp_id_hash[0]=8; credential.nonce[0]=9;
    assert(fj_ecdsa_pubkey(material,credential.public_key));
    assert(fj_hmac_credential_seal(&credential,root,material));
    assert(fj_hmac_store_put(&credential));
    assert(fj_hmac_store_id_exists(NULL,credential.credential_id));
    memset(agreement,0x13,32);
    uint8_t salt[32],iv[16]={0},mac[32]; memset(salt,0x42,32);
    fj_hmac_assertion_request_t req={0}; req.credential_id[0]=7; req.rp_id_hash[0]=8;
    req.extension.platform_public[0]=4; req.extension.salt_len=32;
    memcpy(req.extension.salt_enc,salt,32);
    assert(fj_aes_cbc(agreement,iv,req.extension.salt_enc,32,true));
    assert(fj_hmac_sha256(agreement,32,req.extension.salt_enc,32,mac));
    memcpy(req.extension.salt_auth,mac,16);
    fj_hmac_policy_t policy; fj_hmac_assertion_result_t result;
    assert(fj_hmac_policy_init(&policy,FJ_HMAC_PIN_BUTTON,false,0));
    req.up_requested=true; req.has_pin_auth=true; req.pin_auth[0]=0x31;
    assert(!fj_hmac_assertion(&req,&policy,FJ_HMAC_ROOT_OTP,otp,&result));
    pin_ok=true; assert(!fj_hmac_assertion(&req,&policy,FJ_HMAC_ROOT_OTP,otp,&result));
    req.user_present=true; assert(fj_hmac_assertion(&req,&policy,FJ_HMAC_ROOT_OTP,otp,&result));
    assert(result.auth_data[32]==0x85); verify_signature(&req,&result,credential.public_key);
    verify_output(&req,&result,material+32,salt);
    req.rp_id_hash[1]=1; assert(!fj_hmac_assertion(&req,&policy,FJ_HMAC_ROOT_OTP,otp,&result));
    req.rp_id_hash[1]=0; req.extension.salt_auth[0]^=1;
    assert(!fj_hmac_assertion(&req,&policy,FJ_HMAC_ROOT_OTP,otp,&result));
    req.extension.salt_auth[0]^=1; req.up_requested=false;
    assert(!fj_hmac_assertion(&req,&policy,FJ_HMAC_ROOT_OTP,otp,&result));
    assert(fj_hmac_policy_init(&policy,FJ_HMAC_PIN,false,0));
    req.up_requested=true; req.user_present=false;
    assert(fj_hmac_assertion(&req,&policy,FJ_HMAC_ROOT_OTP,otp,&result));
    assert(result.auth_data[32]==0x84); verify_output(&req,&result,material+32,salt);
    req.up_requested=false;
    assert(fj_hmac_assertion(&req,&policy,FJ_HMAC_ROOT_OTP,otp,&result));
    assert(result.auth_data[32]==0x84);
    req.has_pin_auth=false;
    assert(!fj_hmac_assertion(&req,&policy,FJ_HMAC_ROOT_OTP,otp,&result));
    req.has_pin_auth=true; pin_ok=false;
    assert(!fj_hmac_assertion(&req,&policy,FJ_HMAC_ROOT_OTP,otp,&result));
    pin_ok=true; req.up_requested=true;
    req.user_present=true;
    assert(fj_hmac_assertion(&req,&policy,FJ_HMAC_ROOT_OTP,otp,&result));
    assert(result.auth_data[32]==0x85); verify_output(&req,&result,material+32,salt);
    assert(fj_hmac_policy_init(&policy,FJ_HMAC_AUTO,false,0));
    req.user_present=false; req.has_pin_auth=false;
    req.uv_requested=true;
    assert(!fj_hmac_assertion(&req,&policy,FJ_HMAC_ROOT_OTP,otp,&result));
    req.has_pin_auth=true;
    assert(fj_hmac_assertion(&req,&policy,FJ_HMAC_ROOT_OTP,otp,&result));
    assert((result.auth_data[32] & 4u)!=0);
    req.uv_requested=false; req.has_pin_auth=false;
    assert(fj_hmac_assertion(&req,&policy,FJ_HMAC_ROOT_OTP,otp,&result));
    assert(result.auth_data[32]==0x80); verify_signature(&req,&result,credential.public_key);
    verify_output(&req,&result,material+64,salt);
    req.has_pin_auth=true; pin_ok=false;
    assert(!fj_hmac_assertion(&req,&policy,FJ_HMAC_ROOT_OTP,otp,&result));
    req.has_pin_auth=false;
    assert(!fj_hmac_assertion(&req,&policy,FJ_HMAC_ROOT_OTP,NULL,&result));
    assert(fj_hmac_policy_init(&policy,FJ_HMAC_ARMED,false,0));
    assert(!fj_hmac_assertion(&req,&policy,FJ_HMAC_ROOT_OTP,otp,&result));
    fj_hmac_policy_poll(&policy,false,31);
    fj_hmac_policy_poll(&policy,true,32); fj_hmac_policy_poll(&policy,true,63);
    fj_hmac_policy_poll(&policy,false,64); fj_hmac_policy_poll(&policy,false,95);
    assert(fj_hmac_assertion(&req,&policy,FJ_HMAC_ROOT_OTP,otp,&result));
    assert(result.auth_data[32]==0x80);
    fj_hmac_enroll_request_t enroll={0}; enroll.rp_id_hash[0]=0x55;
    enroll.normal_id_exists=normal_id;
    enroll.pin_auth[0]=0x31; enroll.user_present=true; enroll.has_pin_auth=true;
    fj_hmac_enroll_result_t created;
    pin_ok=true; assert(!fj_hmac_enroll(&enroll,FJ_HMAC_ROOT_OTP,otp,&created));
    enroll.has_pin_auth=false;
    assert(!fj_hmac_enroll(&enroll,FJ_HMAC_ROOT_OTP,otp,&created)); /* locked */
    test_state=FJ_STATE_UNLOCKED; enroll.user_present=false;
    assert(!fj_hmac_enroll(&enroll,FJ_HMAC_ROOT_OTP,otp,&created)); /* no touch */
    enroll.user_present=true;
    assert(fj_hmac_enroll(&enroll,FJ_HMAC_ROOT_OTP,otp,&created));
    assert(created.auth_data[32]==0xc1); /* UP, no unverified UV */
    assert(fj_hmac_store_remove(created.credential_id));
    enroll.has_pin_auth=true;
    test_state=FJ_STATE_UNLOCKED; pin_ok=false;
    assert(!fj_hmac_enroll(&enroll,FJ_HMAC_ROOT_OTP,otp,&created));
    pin_ok=true; enroll.user_present=false;
    assert(!fj_hmac_enroll(&enroll,FJ_HMAC_ROOT_OTP,otp,&created));
    enroll.user_present=true;
    assert(fj_hmac_enroll(&enroll,FJ_HMAC_ROOT_OTP,otp,&created));
    assert(created.auth_data[32]==0xc5 && created.auth_data_len>71);
    fj_hmac_enroll_result_t duplicate;
    assert(!fj_hmac_enroll(&enroll,FJ_HMAC_ROOT_OTP,otp,&duplicate)); /* repeated RNG ID */
    assert(fj_hmac_store_init());
    fj_hmac_credential_t enrolled;
    assert(fj_hmac_store_get(created.credential_id,&enrolled));
    uint8_t enrolled_material[96];
    assert(fj_hmac_credential_open(&enrolled,root,enrolled_material));
    req=(fj_hmac_assertion_request_t){0};
    memcpy(req.credential_id,created.credential_id,16);
    memcpy(req.rp_id_hash,enroll.rp_id_hash,32);
    req.up_requested=true; req.user_present=true; req.has_pin_auth=true; req.pin_auth[0]=0x31;
    req.extension.platform_public[0]=4; req.extension.salt_len=32;
    memcpy(req.extension.salt_enc,salt,32);
    assert(fj_aes_cbc(agreement,iv,req.extension.salt_enc,32,true));
    assert(fj_hmac_sha256(agreement,32,req.extension.salt_enc,32,mac));
    memcpy(req.extension.salt_auth,mac,16);
    assert(fj_hmac_policy_init(&policy,FJ_HMAC_PIN_BUTTON,false,0));
    test_state=FJ_STATE_LOCKED;
    assert(fj_hmac_assertion(&req,&policy,FJ_HMAC_ROOT_OTP,otp,&result));
    verify_signature(&req,&result,created.public_key);
    verify_output(&req,&result,enrolled_material+32,salt);
    assert(test_state==FJ_STATE_LOCKED);
    ctap_roundtrip(&wrapped,otp,salt);
    puts("isolated hmac assertion authorization, outputs and signatures: ok");
    return 0;
}
