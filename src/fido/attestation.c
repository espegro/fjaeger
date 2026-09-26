/*
 * Fjaeger - U2F attestation.
 */
#include <string.h>

#include "attestation.h"
#include "crypto.h"

#include "mbedtls/pk.h"
#include "mbedtls/x509_crt.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/entropy.h"

static mbedtls_pk_context attest_key;
static uint8_t attest_cert[FJ_ATTEST_CERT_MAX];
static size_t attest_cert_len = 0;
static bool initialised = false;

static mbedtls_ctr_drbg_context ctr_drbg;
static mbedtls_entropy_context entropy;

/* Deterministic signing for the attestation block reuses the same ECDSA
 * path as slot signing, but with the attestation private key. We expose
 * it through fj_ecdsa_sign by copying the private scalar. */
static bool attest_priv_scalar(uint8_t out[32]) {
    const mbedtls_pk_type_t type = mbedtls_pk_get_type(&attest_key);
    if (type != MBEDTLS_PK_ECKEY && type != MBEDTLS_PK_ECKEY_DH) return false;

    const mbedtls_ecp_keypair *ecp = mbedtls_pk_ec(attest_key);
    if (!ecp) return false;
    return mbedtls_mpi_write_binary(&ecp->d, out, 32) == 0;
}

bool fj_attest_init(void) {
    int ret;
    char subject[128];
    uint8_t der[FJ_ATTEST_CERT_MAX];

    mbedtls_pk_init(&attest_key);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_entropy_init(&entropy);

    if ((ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                                     (const unsigned char *)"fjaeger-attest", 14)) != 0)
        goto fail;

    /* Generate a fresh P-256 attestation keypair. */
    if ((ret = mbedtls_pk_setup(&attest_key, mbedtls_pk_info_from_type(MBEDTLS_PK_ECKEY))) != 0)
        goto fail;
    if ((ret = mbedtls_ecp_gen_key(MBEDTLS_ECP_DP_SECP256R1,
                                   mbedtls_pk_ec(attest_key),
                                   mbedtls_ctr_drbg_random, &ctr_drbg)) != 0)
        goto fail;

    /* Build a self-signed certificate. */
    mbedtls_x509write_cert cert;
    mbedtls_x509write_crt_init(&cert);
    mbedtls_x509write_crt_set_md_alg(&cert, MBEDTLS_MD_SHA256);
    mbedtls_x509write_crt_set_subject_key(&cert, &attest_key);
    mbedtls_x509write_crt_set_issuer_key(&cert, &attest_key);
    mbedtls_x509write_crt_set_subject_name(&cert, "CN=Fjaeger U2F Attestation");
    mbedtls_x509write_crt_set_issuer_name(&cert, "CN=Fjaeger U2F Attestation");
    mbedtls_x509write_crt_set_version(&cert, MBEDTLS_X509_CRT_VERSION_3);
    mbedtls_x509write_crt_set_validity(&cert, "20240101000000", "20400101000000");
    mbedtls_x509write_crt_set_basic_constraints(&cert, 0, 0);
    mbedtls_x509write_crt_set_key_usage(&cert, MBEDTLS_X509_KU_DIGITAL_SIGNATURE);

    ret = mbedtls_x509write_crt_der(&cert, der, sizeof(der),
                                    mbedtls_ctr_drbg_random, &ctr_drbg);
    mbedtls_x509write_crt_free(&cert);
    if (ret < 0) goto fail;

    /* mbedtls writes the DER at the END of the buffer. */
    size_t der_len = (size_t)ret;
    memcpy(attest_cert, der + sizeof(der) - der_len, der_len);
    attest_cert_len = der_len;

    (void)subject;
    initialised = true;
    return true;

fail:
    mbedtls_pk_free(&attest_key);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
    (void)ret;
    return false;
}

size_t fj_attest_cert(uint8_t out[FJ_ATTEST_CERT_MAX]) {
    if (!initialised) return 0;
    memcpy(out, attest_cert, attest_cert_len);
    return attest_cert_len;
}

bool fj_attest_sign(const uint8_t *block, size_t block_len,
                    uint8_t signature[64]) {
    if (!initialised) return false;

    uint8_t priv[32];
    uint8_t digest[FJ_HASH_LEN];
    if (!attest_priv_scalar(priv)) return false;

    fj_sha256(block, block_len, digest);
    bool ok = fj_ecdsa_sign(priv, digest, signature);
    return ok;
}