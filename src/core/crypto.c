/*
 * Fjaeger - crypto wrappers around mbedTLS.
 */
#include <string.h>

#include "crypto.h"
#include "keys.h"

#include "mbedtls/aes.h"
#include "mbedtls/bignum.h"
#include "mbedtls/ecdsa.h"
#include "mbedtls/ecp.h"
#include "mbedtls/hkdf.h"
#include "mbedtls/md.h"
#include "mbedtls/sha256.h"

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

    /* Deterministic RFC 6979 signing over SHA-256. */
    if ((ret = mbedtls_ecdsa_sign_det_ext(&grp, &r, &s, &d,
                                          digest, FJ_HASH_LEN,
                                          MBEDTLS_MD_SHA256,
                                          NULL, NULL)) != 0)
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
    if ((ret = mbedtls_ecp_mul(&grp, &q, &d, &grp.G, NULL, NULL)) != 0)
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