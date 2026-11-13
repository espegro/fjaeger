#include "combined_backup.h"
#include "crypto.h"
#include <string.h>

#define INNER_LABEL "Fjaeger combined backup hmac v1"
static void put_u32(uint8_t *p,uint32_t x) {
    p[0]=(uint8_t)x; p[1]=(uint8_t)(x>>8); p[2]=(uint8_t)(x>>16); p[3]=(uint8_t)(x>>24);
}
static uint32_t get_u32(const uint8_t *p) {
    return (uint32_t)p[0] | (uint32_t)p[1]<<8 | (uint32_t)p[2]<<16 | (uint32_t)p[3]<<24;
}
_Static_assert(sizeof(bool)==1,"combined backup requires one-byte bool fields");
static bool bool_byte_valid(const bool *p) {
    uint8_t value; memcpy(&value,p,1); return value<=1;
}
bool fj_combined_backup_keys_valid(const fj_backup_payload_t *p) {
    if (!p || p->active_profile_valid!=1 || p->active_profile>=FJ_NUM_PROFILES) return false;
    for (unsigned i=0;i<FJ_NUM_PROFILES;i++) {
        if (!bool_byte_valid(&p->profiles[i].in_use)) return false;
        if (p->profiles[i].in_use && !memchr(p->profiles[i].name,0,sizeof(p->profiles[i].name))) return false;
    }
    if (!p->profiles[p->active_profile].in_use) return false;
    for (unsigned i=0;i<FJ_CTAP2_CREDS;i++) {
        const fj_ctap2_cred_t *c=&p->ctap2[i];
        if (!bool_byte_valid(&c->in_use) || !bool_byte_valid(&c->resident)) return false;
        if (c->in_use && (c->profile_id>=FJ_NUM_PROFILES || !p->profiles[c->profile_id].in_use ||
                          c->rp_len>FJ_RP_MAX || c->user_id_len>FJ_USER_ID_LEN)) return false;
    }
    return true;
}
bool fj_combined_backup_pair_valid(const fj_backup_payload_t *keys,
                                   const fj_hmac_snapshot_t *hmac) {
    if (!fj_combined_backup_keys_valid(keys) || !fj_hmac_snapshot_valid(hmac)) return false;
    for (unsigned i=0;i<FJ_CTAP2_CREDS;i++) {
        if (!keys->ctap2[i].in_use) continue;
        for (unsigned j=0;j<FJ_HMAC_STORE_CAPACITY;j++) {
            if (hmac->entries[j].used &&
                memcmp(keys->ctap2[i].credential_id,
                       hmac->entries[j].credential.credential_id,FJ_CRED_ID_LEN)==0)
                return false;
        }
    }
    return true;
}
static bool header_valid(const uint8_t *p,size_t n) {
    return p && n==FJ_COMBINED_BACKUP_SIZE && memcmp(p,"FJCB",4)==0 &&
           p[4]==1 && !p[5] && !p[6] && !p[7] &&
           get_u32(p+8)==sizeof(fj_backup_payload_t) &&
           get_u32(p+12)==FJ_HMAC_BACKUP_SIZE &&
           !p[28] && !p[29] && !p[30] && !p[31];
}
bool fj_combined_backup_seal(const fj_backup_payload_t *keys,
                             const fj_hmac_snapshot_t *hmac,
                             const uint8_t key[32], const uint8_t nonce[12],
                             uint8_t *out,size_t out_len,
                             uint8_t *workspace,size_t workspace_len) {
    if (!out || out_len<FJ_COMBINED_BACKUP_SIZE || !workspace ||
        workspace_len<FJ_COMBINED_BACKUP_PAYLOAD) return false;
    uint8_t inner[32]={0}, header[FJ_COMBINED_BACKUP_HEADER]={0}, tag[16]={0};
    bool ok=key && nonce && fj_combined_backup_pair_valid(keys,hmac);
    if (ok) {
        memcpy(header,"FJCB",4); header[4]=1;
        put_u32(header+8,sizeof(fj_backup_payload_t)); put_u32(header+12,FJ_HMAC_BACKUP_SIZE);
        memcpy(header+16,nonce,12);
        memcpy(workspace,keys,sizeof(*keys));
        ok=fj_hkdf(key,INNER_LABEL,nonce,12,inner) &&
           fj_hmac_backup_seal(hmac,inner,nonce,workspace+sizeof(*keys),FJ_HMAC_BACKUP_SIZE) &&
           fj_aes_gcm_encrypt_with_aad(key,nonce,header,sizeof(header),workspace,
                                       FJ_COMBINED_BACKUP_PAYLOAD,out+sizeof(header),tag);
        if (ok) {
            memcpy(out,header,sizeof(header));
            memcpy(out+sizeof(header)+FJ_COMBINED_BACKUP_PAYLOAD,tag,sizeof(tag));
        }
    }
    if (!ok) fj_secure_zero(out,FJ_COMBINED_BACKUP_SIZE);
    fj_secure_zero(workspace,FJ_COMBINED_BACKUP_PAYLOAD);
    fj_secure_zero(inner,sizeof(inner)); fj_secure_zero(tag,sizeof(tag));
    return ok;
}
bool fj_combined_backup_open(const uint8_t *blob,size_t blob_len,const uint8_t key[32],
                             fj_backup_payload_t *keys,fj_hmac_snapshot_t *hmac,
                             uint8_t *workspace,size_t workspace_len) {
    if (!keys || !hmac) return false;
    fj_secure_zero(keys,sizeof(*keys)); fj_secure_zero(hmac,sizeof(*hmac));
    if (!workspace || workspace_len<FJ_COMBINED_BACKUP_PAYLOAD) return false;
    uint8_t inner[32]={0}; bool ok=header_valid(blob,blob_len) && key;
    if (ok) {
        const uint8_t *nonce=blob+16;
        ok=fj_hkdf(key,INNER_LABEL,nonce,12,inner) &&
           fj_aes_gcm_decrypt_with_aad(key,nonce,blob+FJ_COMBINED_BACKUP_HEADER+FJ_COMBINED_BACKUP_PAYLOAD,
                                       blob,FJ_COMBINED_BACKUP_HEADER,blob+FJ_COMBINED_BACKUP_HEADER,
                                       FJ_COMBINED_BACKUP_PAYLOAD,workspace);
        if (ok) {
            memcpy(keys,workspace,sizeof(*keys));
            ok=fj_hmac_backup_open(workspace+sizeof(*keys),FJ_HMAC_BACKUP_SIZE,inner,hmac) &&
               fj_combined_backup_pair_valid(keys,hmac);
        }
    }
    if (!ok) { fj_secure_zero(keys,sizeof(*keys)); fj_secure_zero(hmac,sizeof(*hmac)); }
    fj_secure_zero(workspace,FJ_COMBINED_BACKUP_PAYLOAD); fj_secure_zero(inner,sizeof(inner));
    return ok;
}
