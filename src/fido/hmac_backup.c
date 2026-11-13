#include "hmac_backup.h"
#include "crypto.h"
#include <string.h>

bool fj_hmac_snapshot_valid(const fj_hmac_snapshot_t *s) {
    if (!s) return false;
    uint8_t material[FJ_HMAC_MATERIAL_LEN] = {0};
    bool ok = true;
    for (unsigned i=0; i<FJ_HMAC_STORE_CAPACITY; i++) {
        if (s->entries[i].used > 1) { ok=false; break; }
        if (!s->entries[i].used) continue;
        for (unsigned j=0; j<i; j++) {
            if (s->entries[j].used && memcmp(s->entries[i].credential.credential_id,
                    s->entries[j].credential.credential_id,16)==0) { ok=false; break; }
        }
        if (!ok || !fj_hmac_credential_open(&s->entries[i].credential,s->root,material)) { ok=false; break; }
        fj_secure_zero(material,sizeof(material));
    }
    fj_secure_zero(material,sizeof(material)); return ok;
}
static void put_credential(uint8_t **p, const fj_hmac_credential_t *r) {
    memcpy(*p,r->credential_id,16); *p+=16;
    memcpy(*p,r->rp_id_hash,32); *p+=32;
    memcpy(*p,r->public_key,65); *p+=65;
    memcpy(*p,r->nonce,12); *p+=12;
    memcpy(*p,r->ciphertext,96); *p+=96;
    memcpy(*p,r->tag,16); *p+=16;
}
static void get_credential(const uint8_t **p, fj_hmac_credential_t *r) {
    memcpy(r->credential_id,*p,16); *p+=16;
    memcpy(r->rp_id_hash,*p,32); *p+=32;
    memcpy(r->public_key,*p,65); *p+=65;
    memcpy(r->nonce,*p,12); *p+=12;
    memcpy(r->ciphertext,*p,96); *p+=96;
    memcpy(r->tag,*p,16); *p+=16;
}
bool fj_hmac_backup_seal(const fj_hmac_snapshot_t *s,
                         const uint8_t key[32], const uint8_t nonce[12],
                         uint8_t *out, size_t cap) {
    if (!s || !key || !nonce || !out || cap < FJ_HMAC_BACKUP_SIZE || !fj_hmac_snapshot_valid(s)) return false;
    uint8_t header[FJ_HMAC_BACKUP_HEADER] = {'F','J','H','B',1,FJ_HMAC_STORE_CAPACITY,0,0};
    uint8_t payload[FJ_HMAC_BACKUP_PAYLOAD] = {0};
    uint8_t tag[16] = {0};
    memcpy(header+8,nonce,12);
    uint8_t *p=payload; memcpy(p,s->root,32); p+=32;
    for (unsigned i=0;i<FJ_HMAC_STORE_CAPACITY;i++) {
        *p++=s->entries[i].used;
        if (s->entries[i].used) put_credential(&p,&s->entries[i].credential);
        else p+=FJ_HMAC_BACKUP_ENTRY-1;
    }
    bool ok=fj_aes_gcm_encrypt_with_aad(key,nonce,header,sizeof(header),payload,sizeof(payload),
                                       out+sizeof(header),tag);
    if (ok) { memcpy(out,header,sizeof(header)); memcpy(out+sizeof(header)+sizeof(payload),tag,16); }
    else fj_secure_zero(out,FJ_HMAC_BACKUP_SIZE);
    fj_secure_zero(payload,sizeof(payload)); fj_secure_zero(tag,sizeof(tag)); return ok;
}
bool fj_hmac_backup_open(const uint8_t *blob, size_t len,
                         const uint8_t key[32], fj_hmac_snapshot_t *out) {
    if (!out) return false;
    fj_secure_zero(out,sizeof(*out));
    if (!blob || !key || len != FJ_HMAC_BACKUP_SIZE || memcmp(blob,"FJHB",4) ||
        blob[4]!=1 || blob[5]!=FJ_HMAC_STORE_CAPACITY || blob[6] || blob[7]) return false;
    uint8_t payload[FJ_HMAC_BACKUP_PAYLOAD] = {0};
    bool ok=fj_aes_gcm_decrypt_with_aad(key,blob+8,blob+FJ_HMAC_BACKUP_HEADER+FJ_HMAC_BACKUP_PAYLOAD,
            blob,FJ_HMAC_BACKUP_HEADER,blob+FJ_HMAC_BACKUP_HEADER,FJ_HMAC_BACKUP_PAYLOAD,payload);
    if (ok) {
        const uint8_t *p=payload; memcpy(out->root,p,32); p+=32;
        for (unsigned i=0;i<FJ_HMAC_STORE_CAPACITY;i++) {
            out->entries[i].used=*p++;
            get_credential(&p,&out->entries[i].credential);
        }
        ok=fj_hmac_snapshot_valid(out);
    }
    if (!ok) fj_secure_zero(out,sizeof(*out));
    fj_secure_zero(payload,sizeof(payload)); return ok;
}
