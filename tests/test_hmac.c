/* Test production crypto.c against vectors and inject mbedTLS failures. */
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include "crypto.h"
#include "mbedtls/sha256.h"
#include "mbedtls/pkcs5.h"

void fj_random(void *buf, size_t len) { memset(buf, 0x42, len); }
static unsigned fail_at, calls;
static bool fail_now(void) { return ++calls == fail_at; }
int __real_mbedtls_sha256(const unsigned char *, size_t, unsigned char *, int);
int __real_mbedtls_sha256_starts(mbedtls_sha256_context *, int);
int __real_mbedtls_sha256_update(mbedtls_sha256_context *, const unsigned char *, size_t);
int __real_mbedtls_sha256_finish(mbedtls_sha256_context *, unsigned char *);
int __wrap_mbedtls_sha256(const unsigned char *p, size_t n, unsigned char *out, int mode) {
    return fail_now() ? -1 : __real_mbedtls_sha256(p, n, out, mode);
}
int __wrap_mbedtls_sha256_starts(mbedtls_sha256_context *c, int mode) {
    return fail_now() ? -1 : __real_mbedtls_sha256_starts(c, mode);
}
int __wrap_mbedtls_sha256_update(mbedtls_sha256_context *c, const unsigned char *p, size_t n) {
    return fail_now() ? -1 : __real_mbedtls_sha256_update(c, p, n);
}
int __wrap_mbedtls_sha256_finish(mbedtls_sha256_context *c, unsigned char *out) {
    return fail_now() ? -1 : __real_mbedtls_sha256_finish(c, out);
}
static void assert_zero(const void *buf, size_t n) {
    const unsigned char *p = buf;
    for (size_t i = 0; i < n; i++) assert(p[i] == 0);
}
static void expect_hex(const uint8_t out[32], const char *expected) {
    char hex[65];
    for (unsigned i = 0; i < 32; i++) sprintf(hex + 2*i, "%02x", out[i]);
    assert(strcmp(hex, expected) == 0);
}
static void vectors(void) {
    uint8_t key[131], data[50], out[32];
    memset(key, 0x0b, 20);
    assert(fj_hmac_sha256(key,20,(const uint8_t *)"Hi There",8,out));
    expect_hex(out,"b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7");
    assert(fj_hmac_sha256((const uint8_t *)"Jefe",4,
        (const uint8_t *)"what do ya want for nothing?",28,out));
    expect_hex(out,"5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843");
    memset(key,0xaa,sizeof(key)); memset(data,0xdd,sizeof(data));
    assert(fj_hmac_sha256(key,20,data,50,out));
    expect_hex(out,"773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe");
    assert(fj_hmac_sha256(key,131,
        (const uint8_t *)"Test Using Larger Than Block-Size Key - Hash Key First",54,out));
    expect_hex(out,"60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54");
    const unsigned rounds[] = {1,2,4096};
    const char *expected[] = {
        "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b",
        "ae4d0c95af6b46d32d0adff928f06dd02a303f8ef3c251dfd6e2d85a95474c43",
        "c5e478d59288c841aa530db6845c4c8d962893a001ce4e11a4963873aa98134a"
    };
    for (unsigned i=0;i<3;i++) {
        assert(fj_pbkdf2_sha256((const uint8_t *)"password",8,
            (const uint8_t *)"salt",4,rounds[i],out));
        expect_hex(out,expected[i]);
        fj_kdf_t k;
        assert(fj_kdf_begin(&k,(const uint8_t *)"password",8,
            (const uint8_t *)"salt",4,rounds[i]));
        while (k.running) {
            memset(out,0xa5,32);
            assert(!fj_kdf_result(&k,out)); assert_zero(out,32);
            fj_kdf_step(&k);
        }
        assert(fj_kdf_result(&k,out)); expect_hex(out,expected[i]);
        assert_zero(k.password,sizeof(k.password)); assert_zero(k.u,sizeof(k.u));
    }
    uint8_t pw[64], salt[64], ref[32];
    memset(pw,0x61,64); memset(salt,0x62,64);
    assert(fj_pbkdf2_sha256(pw,64,salt,64,2,out));
    assert(mbedtls_pkcs5_pbkdf2_hmac_ext(MBEDTLS_MD_SHA256,pw,64,salt,64,2,32,ref)==0);
    assert(memcmp(out,ref,32)==0);
}
static void failures(void) {
    uint8_t key[131]={1}, out[32];
    for (unsigned keylen=16;keylen<=131;keylen+=115) {
        for (unsigned fail=1;fail<=8+(keylen>64);fail++) {
            calls=0; fail_at=fail; memset(out,0xa5,32);
            assert(!fj_hmac_sha256(key,keylen,key,16,out)); assert_zero(out,32);
        }
    }
    /* Every SHA call in U1, U2 and U3 must fail the entire derivation. */
    for (unsigned fail=1;fail<=24;fail++) {
        calls=0; fail_at=fail; memset(out,0xa5,32);
        assert(!fj_pbkdf2_sha256(key,16,key,16,3,out)); assert_zero(out,32);
        calls=0;
        fj_kdf_t k;
        bool started=fj_kdf_begin(&k,key,16,key,16,3);
        if (started) while (fj_kdf_step(&k)) {}
        assert(k.failed && !k.running);
        assert(!fj_kdf_result(&k,out)); assert_zero(out,32);
        assert_zero(k.password,sizeof(k.password)); assert_zero(k.u,sizeof(k.u));
        assert_zero(k.out,sizeof(k.out));
    }
    calls=0; fail_at=1; assert(!fj_crypto_ok());
    fail_at=0; assert(fj_crypto_ok());
    fj_kdf_t k={0};
    assert(!fj_kdf_result(&k,out));
    assert(fj_kdf_begin(&k,key,16,key,16,1));
    assert(!fj_kdf_begin(&k,key,16,key,16,0));
    assert(!fj_kdf_result(&k,out)); assert_zero(out,32);
    assert(!fj_kdf_begin(&k,key,65,key,16,1));
    assert(!fj_kdf_begin(&k,key,16,key,65,1));
    assert(!fj_kdf_begin(&k,NULL,1,key,16,1));
    assert(!fj_kdf_begin(&k,key,16,NULL,1,1));
}
int main(void) {
    vectors(); failures();
    puts("production HMAC/PBKDF2 vectors, lifecycle and fault injection: ok");
}
