#include "hmac_backup_password.h"
#include "crypto.h"
#include "keys.h"
#include <string.h>

static bool password_ok(const uint8_t *p, size_t n) {
    return p && n >= 8 && n <= 64;
}
/* The salt is bound cryptographically through PBKDF2; the inner AEAD
 * authenticates its own version, capacity and nonce. This outer format
 * accepts exactly one version and canonical reserved bytes. */
bool fj_hmac_password_backup_seal(const fj_hmac_snapshot_t *snapshot,
                                  const uint8_t *password, size_t password_len,
                                  const uint8_t salt[16], const uint8_t nonce[12],
                                  uint8_t *out, size_t capacity) {
    if (!snapshot || !password_ok(password,password_len) || !salt || !nonce ||
        !out || capacity < FJ_HMAC_PASSWORD_BACKUP_SIZE) return false;
    uint8_t key[32] = {0};
    bool ok = fj_pbkdf2_sha256(password,password_len,salt,16,FJ_PBKDF2_ITERATIONS,key) &&
              fj_hmac_backup_seal(snapshot,key,nonce,out+FJ_HMAC_PASSWORD_HEADER,
                                  capacity-FJ_HMAC_PASSWORD_HEADER);
    if (ok) {
        memcpy(out,"FJHP",4); out[4]=1; memset(out+5,0,3); memcpy(out+8,salt,16);
    } else {
        fj_secure_zero(out,FJ_HMAC_PASSWORD_BACKUP_SIZE);
    }
    fj_secure_zero(key,sizeof(key)); return ok;
}
bool fj_hmac_password_backup_open(const uint8_t *blob, size_t len,
                                  const uint8_t *password, size_t password_len,
                                  fj_hmac_snapshot_t *out) {
    if (!out) return false;
    fj_secure_zero(out,sizeof(*out));
    if (!blob || len != FJ_HMAC_PASSWORD_BACKUP_SIZE || !password_ok(password,password_len) ||
        memcmp(blob,"FJHP",4) || blob[4]!=1 || blob[5] || blob[6] || blob[7]) return false;
    uint8_t key[32] = {0};
    bool ok = fj_pbkdf2_sha256(password,password_len,blob+8,16,FJ_PBKDF2_ITERATIONS,key) &&
              fj_hmac_backup_open(blob+FJ_HMAC_PASSWORD_HEADER,FJ_HMAC_BACKUP_SIZE,key,out);
    if (!ok) fj_secure_zero(out,sizeof(*out));
    fj_secure_zero(key,sizeof(key)); return ok;
}
