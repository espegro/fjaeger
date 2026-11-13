#include "hmac_enroll.h"
#include "hmac_store.h"
#include "crypto.h"
#include "keys.h"
#include "pin.h"
#include "state.h"
#include "cbor.h"
#include <string.h>

bool fj_hmac_enroll(const fj_hmac_enroll_request_t *r,fj_hmac_root_mode_t mode,
                    const uint8_t otp[32],fj_hmac_enroll_result_t *out) {
    if (!out) return false;
    fj_secure_zero(out,sizeof(*out));
    uint8_t root[32]={0}, material[FJ_HMAC_MATERIAL_LEN]={0};
    fj_hmac_credential_t credential={0}, existing={0}; bool ok=false;
    if (!r || !r->user_present || !r->normal_id_exists || fj_state_get()!=FJ_STATE_UNLOCKED ||
        (r->has_pin_auth && !fj_pin_verify_user_auth(r->client_data_hash,32,r->pin_auth)) ||
        !fj_hmac_store_open_root(mode,otp,root)) goto done;
    bool unique=false;
    for (unsigned i=0;i<8;i++) {
        fj_random(credential.credential_id,sizeof(credential.credential_id));
        if (!fj_hmac_store_get(credential.credential_id,&existing) &&
            !r->normal_id_exists(r->normal_id_ctx,credential.credential_id)) { unique=true; break; }
    }
    if (!unique || !fj_ecdsa_generate_private(material) ||
        !fj_ecdsa_pubkey(material,credential.public_key)) goto done;
    fj_random(material+32,64);
    fj_random(credential.nonce,sizeof(credential.nonce));
    memcpy(credential.rp_id_hash,r->rp_id_hash,32);
    if (!fj_hmac_credential_seal(&credential,root,material)) goto done;
    memcpy(out->credential_id,credential.credential_id,16);
    memcpy(out->public_key,credential.public_key,65);
    memcpy(out->auth_data,r->rp_id_hash,32);
    out->auth_data[32]=(uint8_t)(0xc1u | (r->has_pin_auth ? 4u : 0u));
    out->auth_data[53]=0; out->auth_data[54]=16;
    memcpy(out->auth_data+55,credential.credential_id,16);
    fj_cbor_writer w; fj_cbor_writer_init(&w,out->auth_data+71,sizeof(out->auth_data)-71);
    fj_cbor_map(&w,5);
    fj_cbor_uint(&w,1); fj_cbor_uint(&w,2);
    fj_cbor_uint(&w,3); fj_cbor_neg(&w,6);
    fj_cbor_neg(&w,0); fj_cbor_uint(&w,1);
    fj_cbor_neg(&w,1); fj_cbor_bstr(&w,credential.public_key+1,32);
    fj_cbor_neg(&w,2); fj_cbor_bstr(&w,credential.public_key+33,32);
    fj_cbor_map(&w,1); fj_cbor_tstr(&w,"hmac-secret"); fj_cbor_bool(&w,true);
    if (!fj_cbor_ok(&w)) goto done;
    out->auth_data_len=71+w.len;
    /* Commit before reporting success: a crash must not issue an unusable ID. */
    if (!fj_hmac_store_put(&credential)) goto done;
    ok=true;
done:
    if (!ok) fj_secure_zero(out,sizeof(*out));
    fj_secure_zero(root,sizeof(root)); fj_secure_zero(material,sizeof(material));
    fj_secure_zero(&credential,sizeof(credential)); fj_secure_zero(&existing,sizeof(existing));
    return ok;
}
