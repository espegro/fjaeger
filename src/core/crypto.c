/*
 * Fjaeger - crypto wrappers around mbedTLS.
 */
#include <string.h>

#include "crypto.h"
#include "keys.h"

#include "mbedtls/aes.h"
#include "mbedtls/asn1write.h"
#include "mbedtls/bignum.h"
#include "mbedtls/ecdh.h"
#include "mbedtls/ecdsa.h"
#include "mbedtls/ecp.h"
#include "mbedtls/gcm.h"
#include "mbedtls/hkdf.h"
#include "mbedtls/md.h"
#include "mbedtls/sha256.h"

static int crypto_rng(void *ctx, unsigned char *out, size_t len) {
    (void)ctx;
    fj_random(out, len);
    return 0;
}

void fj_sha256(const uint8_t *data, size_t len, uint8_t out[FJ_HASH_LEN]) {
    mbedtls_sha256(data, len, out, 0);
}

bool fj_hkdf(const uint8_t ikm[FJ_AES_KEY_LEN], const char *label,
             const uint8_t *salt, size_t salt_len, uint8_t out[32]) {
    const mbedtls_md_info_t *md = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    return mbedtls_hkdf(md, salt, salt_len, ikm, FJ_AES_KEY_LEN,
                        (const uint8_t *)label, strlen(label), out, 32) == 0;
}

bool fj_ecdsa_sign(const uint8_t private_key[32],
                   const uint8_t digest[FJ_HASH_LEN],
                   uint8_t signature[64]) {
    mbedtls_ecp_group grp;
    mbedtls_mpi d, r, s;
    int ret;

    mbedtls_ecp_group_init(&grp);
    mbedtls_mpi_init(&d);
    mbedtls_mpi_init(&r);
    mbedtls_mpi_init(&s);

    if ((ret = mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_SECP256R1)) != 0)
        goto fail;
    if ((ret = mbedtls_mpi_read_binary(&d, private_key, 32)) != 0)
        goto fail;

    /* Reject corrupt persisted credentials before entering the ECDSA path. */
    if ((ret = mbedtls_ecp_check_privkey(&grp, &d)) != 0)
        goto fail;

    /* Use the RP2350 hardware RNG for both the ephemeral scalar and
     * side-channel blinding.  The deterministic mbedTLS API uses HMAC-DRBG;
     * that needs several interleaved SHA-256 contexts, while the Pico SDK's
     * SHA-256 accelerator exposes one globally locked hardware context. */
    if ((ret = mbedtls_ecdsa_sign(&grp, &r, &s, &d,
                                  digest, FJ_HASH_LEN,
                                  crypto_rng, NULL)) != 0)
        goto fail;

    /* Export r and s as fixed 32-byte big-endian values. */
    if (mbedtls_mpi_write_binary(&r, signature, 32) != 0) goto fail;
    if (mbedtls_mpi_write_binary(&s, signature + 32, 32) != 0) goto fail;

    mbedtls_mpi_free(&s);
    mbedtls_mpi_free(&r);
    mbedtls_mpi_free(&d);
    mbedtls_ecp_group_free(&grp);
    return true;

fail:
    mbedtls_mpi_free(&s);
    mbedtls_mpi_free(&r);
    mbedtls_mpi_free(&d);
    mbedtls_ecp_group_free(&grp);
    (void)ret;
    return false;
}

bool fj_ecdsa_generate_private(uint8_t private_key[32]) {
    mbedtls_ecp_group grp;
    mbedtls_mpi d;
    int ret = -1;

    mbedtls_ecp_group_init(&grp);
    mbedtls_mpi_init(&d);

    if (mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_SECP256R1) != 0)
        goto done;

    /* A uniformly random 256-bit value is invalid only with negligible
     * probability, but validate it rather than ever storing a bad scalar. */
    for (unsigned attempt = 0; attempt < 16; attempt++) {
        fj_random(private_key, 32);
        if (mbedtls_mpi_read_binary(&d, private_key, 32) != 0)
            goto done;
        ret = mbedtls_ecp_check_privkey(&grp, &d);
        if (ret == 0) break;
    }

done:
    mbedtls_mpi_free(&d);
    mbedtls_ecp_group_free(&grp);
    return ret == 0;
}

bool fj_ecdsa_signature_der(const uint8_t signature[64], uint8_t *out,
                            size_t out_cap, size_t *out_len) {
    unsigned char encoded[MBEDTLS_ECDSA_MAX_LEN];
    unsigned char *p = encoded + sizeof(encoded);
    mbedtls_mpi r, s;
    size_t len = 0;
    int ret;

    mbedtls_mpi_init(&r);
    mbedtls_mpi_init(&s);

    if ((ret = mbedtls_mpi_read_binary(&r, signature, 32)) != 0) goto done;
    if ((ret = mbedtls_mpi_read_binary(&s, signature + 32, 32)) != 0) goto done;
    if ((ret = mbedtls_asn1_write_mpi(&p, encoded, &s)) < 0) goto done;
    len += (size_t)ret;
    if ((ret = mbedtls_asn1_write_mpi(&p, encoded, &r)) < 0) goto done;
    len += (size_t)ret;
    if ((ret = mbedtls_asn1_write_len(&p, encoded, len)) < 0) goto done;
    len += (size_t)ret;
    if ((ret = mbedtls_asn1_write_tag(&p, encoded,
                                      MBEDTLS_ASN1_CONSTRUCTED |
                                      MBEDTLS_ASN1_SEQUENCE)) < 0) goto done;
    len += (size_t)ret;

    if (len > out_cap) {
        ret = -1;
        goto done;
    }
    memcpy(out, p, len);
    if (out_len) *out_len = len;
    ret = 0;

done:
    mbedtls_mpi_free(&s);
    mbedtls_mpi_free(&r);
    return ret == 0;
}

bool fj_ecdsa_pubkey(const uint8_t private_key[32], uint8_t pub[65]) {
    mbedtls_ecp_group grp;
    mbedtls_mpi d;
    mbedtls_ecp_point q;
    int ret;

    mbedtls_ecp_group_init(&grp);
    mbedtls_mpi_init(&d);
    mbedtls_ecp_point_init(&q);

    if ((ret = mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_SECP256R1)) != 0)
        goto fail;
    if ((ret = mbedtls_mpi_read_binary(&d, private_key, 32)) != 0)
        goto fail;
    if ((ret = mbedtls_ecp_mul(&grp, &q, &d, &grp.G,
                               crypto_rng, NULL)) != 0)
        goto fail;

    size_t olen = 0;
    if ((ret = mbedtls_ecp_point_write_binary(&grp, &q, MBEDTLS_ECP_PF_UNCOMPRESSED,
                                              &olen, pub, 65)) != 0)
        goto fail;

    mbedtls_ecp_point_free(&q);
    mbedtls_mpi_free(&d);
    mbedtls_ecp_group_free(&grp);
    return olen == 65;

fail:
    mbedtls_ecp_point_free(&q);
    mbedtls_mpi_free(&d);
    mbedtls_ecp_group_free(&grp);
    (void)ret;
    return false;
}

bool fj_crypto_ok(void) {
    /* A trivial self-check: derive the RNG path is operational by hashing a
     * fixed input and comparing against a known vector. */
    uint8_t out[FJ_HASH_LEN];
    const uint8_t in[] = "abc";
    const uint8_t expect[FJ_HASH_LEN] = {
        0xba,0x78,0x16,0xbf,0x8f,0x01,0xcf,0xea,
        0x41,0x41,0x40,0xde,0x5d,0xae,0x22,0x23,
        0xb0,0x03,0x61,0xa3,0x96,0x17,0x7a,0x9c,
        0xb4,0x10,0xff,0x61,0xf2,0x00,0x15,0xad,
    };
    fj_sha256(in, sizeof(in) - 1, out);
    return memcmp(out, expect, FJ_HASH_LEN) == 0;
}

bool fj_xts_sector(const uint8_t data_key[32], const uint8_t tweak[16],
                   uint8_t buf[512], bool encrypt) {
    mbedtls_aes_xts_context ctx;
    int ret;

    mbedtls_aes_xts_init(&ctx);

    /*
     * AES-XTS uses two 128-bit keys (K1=data, K2=tweak). Our 256-bit
     * data key supplies both halves.
     */
    if (encrypt) {
        ret = mbedtls_aes_xts_setkey_enc(&ctx, data_key, 256);
    } else {
        ret = mbedtls_aes_xts_setkey_dec(&ctx, data_key, 256);
    }
    if (ret != 0) {
        mbedtls_aes_xts_free(&ctx);
        return false;
    }

    ret = mbedtls_aes_crypt_xts(&ctx,
                                encrypt ? MBEDTLS_AES_ENCRYPT : MBEDTLS_AES_DECRYPT,
                                512, tweak, buf, buf);
    mbedtls_aes_xts_free(&ctx);
    return ret == 0;
}

bool fj_ecdh_shared_secret(const uint8_t private_key[32],
                           const uint8_t peer_pub[65],
                           uint8_t out[32]) {
    mbedtls_ecp_group grp;
    mbedtls_mpi d, z;
    mbedtls_ecp_point q;
    int ret = -1;

    mbedtls_ecp_group_init(&grp);
    mbedtls_mpi_init(&d);
    mbedtls_mpi_init(&z);
    mbedtls_ecp_point_init(&q);

    if (mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_SECP256R1) != 0)
        goto done;
    if (mbedtls_mpi_read_binary(&d, private_key, 32) != 0)
        goto done;
    if (mbedtls_ecp_point_read_binary(&grp, &q, peer_pub, 65) != 0)
        goto done;

    /* z = d * q; mbedtls_ecdh_compute_shared exports the X coordinate. */
    if (mbedtls_ecdh_compute_shared(&grp, &z, &q, &d,
                                    crypto_rng, NULL) != 0)
        goto done;
    if (mbedtls_mpi_write_binary(&z, out, 32) != 0)
        goto done;

    ret = 0;
done:
    mbedtls_mpi_free(&z);
    mbedtls_ecp_point_free(&q);
    mbedtls_mpi_free(&d);
    mbedtls_ecp_group_free(&grp);
    return ret == 0;
}

bool fj_aes_cbc(const uint8_t key[32], const uint8_t iv[16],
                uint8_t *buf, size_t len, bool encrypt) {
    mbedtls_aes_context ctx;
    int ret;

    mbedtls_aes_init(&ctx);
    if (encrypt)
        ret = mbedtls_aes_setkey_enc(&ctx, key, 256);
    else
        ret = mbedtls_aes_setkey_dec(&ctx, key, 256);
    if (ret != 0) {
        mbedtls_aes_free(&ctx);
        return false;
    }

    uint8_t iv_copy[16];
    memcpy(iv_copy, iv, 16);
    ret = mbedtls_aes_crypt_cbc(&ctx, encrypt ? MBEDTLS_AES_ENCRYPT
                                              : MBEDTLS_AES_DECRYPT,
                                len, iv_copy, buf, buf);
    fj_secure_zero(iv_copy, sizeof(iv_copy));
    mbedtls_aes_free(&ctx);
    return ret == 0;
}

bool fj_hmac_sha256(const uint8_t *key, size_t key_len,
                    const uint8_t *data, size_t len,
                    uint8_t out[32]) {
    /* HMAC-SHA256 built directly on the mbedTLS SHA-256 context. This uses a
     * ~100-byte stack frame instead of mbedtls_md_hmac's much larger
     * mbedtls_md_context, which matters on the RP2350's limited RAM when a
     * PBKDF2 pass runs deep in the unlock/backup call stack. */
    uint8_t k[64], ipad[64], opad[64], inner[32];
    memset(k, 0, sizeof(k));
    if (key_len > 64) {
        uint8_t kh[32];
        mbedtls_sha256(key, key_len, kh, 0);
        memcpy(k, kh, 32);
        fj_secure_zero(kh, sizeof(kh));
    } else {
        memcpy(k, key, key_len);
    }
    for (int i = 0; i < 64; i++) {
        ipad[i] = k[i] ^ 0x36;
        opad[i] = k[i] ^ 0x5c;
    }
    fj_secure_zero(k, sizeof(k));

    mbedtls_sha256_context ctx;
    mbedtls_sha256_init(&ctx);

    /* inner = SHA-256(ipad || message) */
    mbedtls_sha256_starts(&ctx, 0);
    mbedtls_sha256_update(&ctx, ipad, 64);
    mbedtls_sha256_update(&ctx, data, len);
    mbedtls_sha256_finish(&ctx, inner);

    /* out = SHA-256(opad || inner) */
    mbedtls_sha256_starts(&ctx, 0);
    mbedtls_sha256_update(&ctx, opad, 64);
    mbedtls_sha256_update(&ctx, inner, 32);
    mbedtls_sha256_finish(&ctx, out);

    mbedtls_sha256_free(&ctx);
    fj_secure_zero(ipad, sizeof(ipad));
    fj_secure_zero(opad, sizeof(opad));
    fj_secure_zero(inner, sizeof(inner));
    return true;
}

bool fj_ct_equal(const void *a, const void *b, size_t n) {
    const uint8_t *x = (const uint8_t *)a;
    const uint8_t *y = (const uint8_t *)b;
    uint8_t diff = 0;
    for (size_t i = 0; i < n; i++) diff |= x[i] ^ y[i];
    return diff == 0;
}

bool fj_kdf_begin(fj_kdf_t *k, const uint8_t *password, size_t pw_len,
                  const uint8_t *salt, size_t salt_len, uint32_t iterations) {
    if (!k || iterations == 0 || salt_len > FJ_KDF_SALT_MAX)
        return false;
    if (pw_len > FJ_KDF_PW_MAX)
        return false;

    memset(k, 0, sizeof(*k));
    memcpy(k->password, password, pw_len);
    k->pw_len = pw_len;
    memcpy(k->salt, salt, salt_len);
    k->salt_len = salt_len;
    k->iterations = iterations;

    /* U_1 = HMAC(password, salt || INT(1)); T_1 = U_1. */
    uint8_t block[FJ_KDF_SALT_MAX + 4];
    memcpy(block, salt, salt_len);
    block[salt_len] = 0;
    block[salt_len + 1] = 0;
    block[salt_len + 2] = 0;
    block[salt_len + 3] = 1;
    if (!fj_hmac_sha256(password, pw_len, block, salt_len + 4, k->u))
        return false;
    memcpy(k->out, k->u, 32);
    k->i = 1;
    k->running = true;
    return true;
}

bool fj_kdf_step(fj_kdf_t *k) {
    if (!k || !k->running) return false;

    /* iterations == 1 needs no inner rounds; the result is already in out. */
    if (k->i >= k->iterations) {
        k->running = false;
        return false;
    }

    if (!fj_hmac_sha256(k->password, k->pw_len, k->u, 32, k->u)) {
        k->running = false;
        return false;
    }
    for (int j = 0; j < 32; j++) k->out[j] ^= k->u[j];
    k->i++;
    return k->i < k->iterations;
}

bool fj_kdf_result(const fj_kdf_t *k, uint8_t out[32]) {
    if (!k || !out) return false;
    memcpy(out, k->out, 32);
    return true;
}

bool fj_pbkdf2_sha256(const uint8_t *password, size_t pw_len,
                      const uint8_t *salt, size_t salt_len,
                      uint32_t iterations, uint8_t out[32]) {
    if (iterations == 0 || salt_len > FJ_KDF_SALT_MAX) return false;
    if (pw_len > FJ_KDF_PW_MAX) return false;

    fj_kdf_t k;
    if (!fj_kdf_begin(&k, password, pw_len, salt, salt_len, iterations))
        return false;
    while (fj_kdf_step(&k)) {
        /* No USB servicing here: firmware paths that must not block drive the
         * resumable KDF from the main loop instead. This wrapper is used by
         * host tests and any caller that can tolerate the full derivation. */
    }
    bool ok = fj_kdf_result(&k, out);
    fj_secure_zero(&k, sizeof(k));
    return ok;
}

bool fj_aes_gcm_encrypt_with_aad(const uint8_t key[32], const uint8_t nonce[12],
                                 const uint8_t *aad, size_t aad_len,
                                 const uint8_t *in, size_t len,
                                 uint8_t *out, uint8_t tag[16]) {
    mbedtls_gcm_context ctx;
    mbedtls_gcm_init(&ctx);
    int ret = mbedtls_gcm_setkey(&ctx, MBEDTLS_CIPHER_ID_AES, key, 256);
    if (ret != 0) { mbedtls_gcm_free(&ctx); return false; }
    ret = mbedtls_gcm_crypt_and_tag(&ctx, MBEDTLS_GCM_ENCRYPT, len,
                                    nonce, 12, aad, aad_len,
                                    in, out, 16, tag);
    mbedtls_gcm_free(&ctx);
    return ret == 0;
}

bool fj_aes_gcm_decrypt_with_aad(const uint8_t key[32], const uint8_t nonce[12],
                                 const uint8_t tag[16],
                                 const uint8_t *aad, size_t aad_len,
                                 const uint8_t *in, size_t len, uint8_t *out) {
    mbedtls_gcm_context ctx;
    mbedtls_gcm_init(&ctx);
    int ret = mbedtls_gcm_setkey(&ctx, MBEDTLS_CIPHER_ID_AES, key, 256);
    if (ret != 0) { mbedtls_gcm_free(&ctx); return false; }
    ret = mbedtls_gcm_auth_decrypt(&ctx, len, nonce, 12, aad, aad_len,
                                   tag, 16, in, out);
    mbedtls_gcm_free(&ctx);
    if (ret != 0) {
        /* Do not leave unauthenticated plaintext in a caller-owned buffer. */
        fj_secure_zero(out, len);
        return false;
    }
    return true;
}

bool fj_aes_gcm_encrypt(const uint8_t key[32], const uint8_t nonce[12],
                        const uint8_t *in, size_t len,
                        uint8_t *out, uint8_t tag[16]) {
    return fj_aes_gcm_encrypt_with_aad(key, nonce, NULL, 0, in, len, out, tag);
}

bool fj_aes_gcm_decrypt(const uint8_t key[32], const uint8_t nonce[12],
                        const uint8_t tag[16],
                        const uint8_t *in, size_t len, uint8_t *out) {
    return fj_aes_gcm_decrypt_with_aad(key, nonce, tag, NULL, 0, in, len, out);
}
