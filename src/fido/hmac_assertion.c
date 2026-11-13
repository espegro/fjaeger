#include "hmac_assertion.h"
#include "hmac_store.h"
#include "hmac_secret.h"
#include "pin.h"
#include "crypto.h"
#include "cbor.h"
#include <string.h>

bool fj_hmac_preflight(const uint8_t id[16],const uint8_t rp[32],const uint8_t client[32],
                       const fj_hmac_policy_t *policy,fj_hmac_root_mode_t mode,
                       const uint8_t otp[32],fj_hmac_assertion_result_t *out) {
    if (!out) return false;
    fj_secure_zero(out,sizeof(*out));
    uint8_t root[32]={0},material[FJ_HMAC_MATERIAL_LEN]={0},pub[65]={0};
    uint8_t data[69]={0},digest[32]={0},sig[64]={0};
    fj_hmac_credential_t cred={0}; bool ok=false;
    if (!id || !rp || !client || !policy ||
        (policy->mode!=FJ_HMAC_AUTO && policy->mode!=FJ_HMAC_ARMED) ||
        fj_hmac_policy_decide(policy,false,false)!=FJ_HMAC_ALLOW ||
        !fj_hmac_store_get(id,&cred) || !fj_ct_equal(cred.rp_id_hash,rp,32) ||
        !fj_hmac_store_open_root(mode,otp,root) ||
        !fj_hmac_credential_open(&cred,root,material) ||
        !fj_ecdsa_pubkey(material,pub) || !fj_ct_equal(pub,cred.public_key,sizeof(pub))) goto done;
    memcpy(out->auth_data,rp,32); out->auth_data_len=37; /* UP=UV=0 */
    memcpy(data,out->auth_data,37); memcpy(data+37,client,32);
    fj_sha256(data,sizeof(data),digest);
    if (!fj_ecdsa_sign(material,digest,sig) ||
        !fj_ecdsa_signature_der(sig,out->signature,sizeof(out->signature),&out->signature_len)) goto done;
    ok=true;
done:
    if (!ok) fj_secure_zero(out,sizeof(*out));
    fj_secure_zero(root,sizeof(root)); fj_secure_zero(material,sizeof(material));
    fj_secure_zero(pub,sizeof(pub)); fj_secure_zero(data,sizeof(data));
    fj_secure_zero(digest,sizeof(digest)); fj_secure_zero(sig,sizeof(sig));
    fj_secure_zero(&cred,sizeof(cred)); return ok;
}

bool fj_hmac_assertion(const fj_hmac_assertion_request_t *r,const fj_hmac_policy_t *policy,
                       fj_hmac_root_mode_t mode,const uint8_t otp[32],
                       fj_hmac_assertion_result_t *out) {
    if (!out) return false;
    fj_secure_zero(out,sizeof(*out));
    uint8_t root[32]={0},material[FJ_HMAC_MATERIAL_LEN]={0},shared[32]={0},
            encrypted[64]={0},pub[65]={0},digest[32]={0},sig[64]={0},
            signed_data[sizeof(out->auth_data)+32]={0};
    fj_hmac_credential_t credential={0}; bool ok=false;
    if (!r || !policy || (r->extension.salt_len!=32 && r->extension.salt_len!=64)) goto done;
    bool uv=r->has_pin_auth && fj_pin_verify_user_auth(r->client_data_hash,32,r->pin_auth);
    /* An explicitly supplied invalid authorization is never ignored, even in
     * an unattended policy. Only explicit auto/armed permits up=false. */
    if ((r->has_pin_auth && !uv) || (r->uv_requested && !uv) ||
        (r->up_requested && !r->user_present &&
         (policy->mode==FJ_HMAC_PIN || policy->mode==FJ_HMAC_PIN_BUTTON)) ||
        (!r->up_requested && policy->mode!=FJ_HMAC_AUTO && policy->mode!=FJ_HMAC_ARMED) ||
        fj_hmac_policy_decide(policy,uv,r->user_present)!=FJ_HMAC_ALLOW) goto done;
    if (!fj_hmac_store_get(r->credential_id,&credential) ||
        !fj_ct_equal(credential.rp_id_hash,r->rp_id_hash,32) ||
        !fj_hmac_store_open_root(mode,otp,root) ||
        !fj_hmac_credential_open(&credential,root,material) ||
        !fj_ecdsa_pubkey(material,pub) || !fj_ct_equal(pub,credential.public_key,sizeof(pub)) ||
        !fj_pin_shared_secret(r->extension.platform_public,shared) ||
        !fj_hmac_secret_v1(shared,material+(uv ? 32 : 64),r->extension.salt_enc,
                           r->extension.salt_len,r->extension.salt_auth,encrypted,sizeof(encrypted))) goto done;
    memcpy(out->auth_data,r->rp_id_hash,32);
    out->auth_data[32]=(uint8_t)(0x80u | (r->user_present ? 1u : 0u) | (uv ? 4u : 0u));
    /* signCount remains zero, as for the normal credential store. */
    fj_cbor_writer w; fj_cbor_writer_init(&w,out->auth_data+37,sizeof(out->auth_data)-37);
    fj_cbor_map(&w,1); fj_cbor_tstr(&w,"hmac-secret");
    fj_cbor_bstr(&w,encrypted,r->extension.salt_len);
    if (!fj_cbor_ok(&w)) goto done;
    out->auth_data_len=37+w.len;
    memcpy(signed_data,out->auth_data,out->auth_data_len);
    memcpy(signed_data+out->auth_data_len,r->client_data_hash,32);
    fj_sha256(signed_data,out->auth_data_len+32,digest);
    if (!fj_ecdsa_sign(material,digest,sig) ||
        !fj_ecdsa_signature_der(sig,out->signature,sizeof(out->signature),&out->signature_len)) goto done;
    ok=true;
done:
    if (!ok) fj_secure_zero(out,sizeof(*out));
    fj_secure_zero(root,sizeof(root)); fj_secure_zero(material,sizeof(material));
    fj_secure_zero(shared,sizeof(shared)); fj_secure_zero(encrypted,sizeof(encrypted));
    fj_secure_zero(pub,sizeof(pub)); fj_secure_zero(digest,sizeof(digest));
    fj_secure_zero(sig,sizeof(sig)); fj_secure_zero(signed_data,sizeof(signed_data));
    fj_secure_zero(&credential,sizeof(credential)); return ok;
}
