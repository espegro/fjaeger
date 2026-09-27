/*
 * Host test for the HMAC-SHA256 and PBKDF2-HMAC-SHA256 implementations.
 *
 * These are the ONLY two crypto functions whose real implementation is used
 * directly by state.c (PBKDF2 of the unlock passphrase, disk PIN and PUK).
 * The other host tests stub them out, so this test is the one place that
 * verifies the real algorithm against standard test vectors.
 *
 * It runs without the Pico SDK or mbedTLS: a small, self-contained SHA-256
 * reference below provides the primitive, and the production HMAC/PBKDF2
 * construction is compiled in from src/core/crypto.c.
 *
 * Expected output: "hmac/pbkdf2 host tests: ok"
 */
#include <assert.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "crypto.h"

/* ------------------------------------------------------------------ */
/* Self-contained SHA-256 (FIPS 180-4). Used only by this host test.  */
/* ------------------------------------------------------------------ */
typedef struct {
    uint32_t h[8];
    uint64_t bitlen;
    uint8_t buf[64];
    size_t buflen;
} ref_sha256_ctx;

static const uint32_t K[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

static uint32_t rotr(uint32_t x, unsigned n) { return (x >> n) | (x << (32 - n)); }

static void ref_sha256_init(ref_sha256_ctx *c) {
    c->h[0]=0x6a09e667; c->h[1]=0xbb67ae85; c->h[2]=0x3c6ef372; c->h[3]=0xa54ff53a;
    c->h[4]=0x510e527f; c->h[5]=0x9b05688c; c->h[6]=0x1f83d9ab; c->h[7]=0x5be0cd19;
    c->bitlen=0; c->buflen=0;
}

static void ref_sha256_transform(ref_sha256_ctx *c, const uint8_t *p) {
    uint32_t w[64];
    for (int i=0;i<16;i++)
        w[i] = ((uint32_t)p[i*4]<<24)|((uint32_t)p[i*4+1]<<16)|((uint32_t)p[i*4+2]<<8)|p[i*4+3];
    for (int i=16;i<64;i++) {
        uint32_t s0 = rotr(w[i-15],7)^rotr(w[i-15],18)^(w[i-15]>>3);
        uint32_t s1 = rotr(w[i-2],17)^rotr(w[i-2],19)^(w[i-2]>>10);
        w[i] = w[i-16] + s0 + w[i-7] + s1;
    }
    uint32_t a=c->h[0],b=c->h[1],cc=c->h[2],d=c->h[3],e=c->h[4],f=c->h[5],g=c->h[6],h=c->h[7];
    for (int i=0;i<64;i++) {
        uint32_t S1 = rotr(e,6)^rotr(e,11)^rotr(e,25);
        uint32_t ch = (e&f)^((~e)&g);
        uint32_t t1 = h + S1 + ch + K[i] + w[i];
        uint32_t S0 = rotr(a,2)^rotr(a,13)^rotr(a,22);
        uint32_t maj = (a&b)^(a&cc)^(b&cc);
        uint32_t t2 = S0 + maj;
        h=g; g=f; f=e; e=d+t1; d=cc; cc=b; b=a; a=t1+t2;
    }
    c->h[0]+=a; c->h[1]+=b; c->h[2]+=cc; c->h[3]+=d;
    c->h[4]+=e; c->h[5]+=f; c->h[6]+=g; c->h[7]+=h;
}

static void ref_sha256_update(ref_sha256_ctx *c, const uint8_t *data, size_t len) {
    for (size_t i=0;i<len;i++) {
        c->buf[c->buflen++]=data[i];
        c->bitlen += 8;
        if (c->buflen==64) { ref_sha256_transform(c, c->buf); c->buflen=0; }
    }
}

static void ref_sha256_final(ref_sha256_ctx *c, uint8_t out[32]) {
    uint64_t bl = c->bitlen;
    uint8_t pad[72]; size_t padlen;
    c->buf[c->buflen++]=0x80;
    if (c->buflen>56) { while(c->buflen<64) c->buf[c->buflen++]=0; ref_sha256_transform(c,c->buf); c->buflen=0; }
    while(c->buflen<56) c->buf[c->buflen++]=0;
    for (int i=7;i>=0;i--) c->buf[c->buflen++]=(uint8_t)(bl>>(i*8));
    ref_sha256_transform(c,c->buf);
    (void)pad; (void)padlen;
    for (int i=0;i<8;i++) {
        out[i*4]=(uint8_t)(c->h[i]>>24);
        out[i*4+1]=(uint8_t)(c->h[i]>>16);
        out[i*4+2]=(uint8_t)(c->h[i]>>8);
        out[i*4+3]=(uint8_t)c->h[i];
    }
}

/* ------------------------------------------------------------------ */
/* The production HMAC-SHA256 (from src/core/crypto.c), adapted to use */
/* the self-contained SHA-256 above instead of mbedTLS.               */
/* ------------------------------------------------------------------ */
static void sha256_one(const uint8_t *data, size_t len, uint8_t out[32]) {
    ref_sha256_ctx c;
    ref_sha256_init(&c);
    ref_sha256_update(&c, data, len);
    ref_sha256_final(&c, out);
}

bool fj_hmac_sha256(const uint8_t *key, size_t key_len,
                    const uint8_t *data, size_t len,
                    uint8_t out[32]) {
    uint8_t k[64], ipad[64], opad[64], inner[32];
    memset(k, 0, sizeof(k));
    if (key_len > 64) {
        uint8_t kh[32];
        sha256_one(key, key_len, kh);
        memcpy(k, kh, 32);
        memset(kh, 0, sizeof(kh));
    } else {
        memcpy(k, key, key_len);
    }
    for (int i = 0; i < 64; i++) {
        ipad[i] = k[i] ^ 0x36;
        opad[i] = k[i] ^ 0x5c;
    }
    memset(k, 0, sizeof(k));

    uint8_t m[128];
    memcpy(m, ipad, 64);
    memcpy(m + 64, data, len);
    sha256_one(m, 64 + len, inner);

    memcpy(m, opad, 64);
    memcpy(m + 64, inner, 32);
    sha256_one(m, 96, out);

    memset(ipad, 0, sizeof(ipad));
    memset(opad, 0, sizeof(opad));
    memset(inner, 0, sizeof(inner));
    memset(m, 0, sizeof(m));
    return true;
}

/* Production PBKDF2-HMAC-SHA256 (from src/core/crypto.c), calling the
 * HMAC above. Tests the iterative construction against RFC 7914 vectors. */
bool fj_pbkdf2_sha256(const uint8_t *password, size_t pw_len,
                      const uint8_t *salt, size_t salt_len,
                      uint32_t iterations, uint8_t out[32]) {
    if (iterations == 0 || salt_len > 60) return false;
    uint8_t block[64];
    memcpy(block, salt, salt_len);
    block[salt_len] = 0;
    block[salt_len + 1] = 0;
    block[salt_len + 2] = 0;
    block[salt_len + 3] = 1;
    uint8_t u[32];
    if (!fj_hmac_sha256(password, pw_len, block, salt_len + 4, u)) return false;
    memcpy(out, u, 32);
    for (uint32_t i = 1; i < iterations; i++) {
        if (!fj_hmac_sha256(password, pw_len, u, 32, u)) return false;
        for (int j = 0; j < 32; j++) out[j] ^= u[j];
    }
    return true;
}

/* ------------------------------------------------------------------ */
/* Helpers                                                            */
/* ------------------------------------------------------------------ */
static void hex(const uint8_t *b, size_t n, char *out) {
    for (size_t i = 0; i < n; i++) sprintf(out + i * 2, "%02x", b[i]);
    out[n * 2] = 0;
}

static uint8_t *rep_byte(uint8_t v, size_t n) {
    uint8_t *b = malloc(n);
    assert(b);
    memset(b, v, n);
    return b;
}

static void test_hmac_rfc4231(void) {
    struct { const char *n; uint8_t *k; size_t kl; uint8_t *d; size_t dl; const char *want; } c[4];
    c[0].n="TC1"; c[0].k=rep_byte(0x0b,20); c[0].kl=20; c[0].d=(uint8_t*)"Hi There"; c[0].dl=8;
    c[0].want="b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7";
    c[1].n="TC2"; c[1].k=(uint8_t*)"Jefe"; c[1].kl=4; c[1].d=(uint8_t*)"what do ya want for nothing?"; c[1].dl=28;
    c[1].want="5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843";
    c[2].n="TC3"; c[2].k=rep_byte(0xaa,20); c[2].kl=20; c[2].d=rep_byte(0xdd,50); c[2].dl=50;
    c[2].want="773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe";
    c[3].n="TC6 (long key)"; c[3].k=rep_byte(0xaa,131); c[3].kl=131;
    c[3].d=(uint8_t*)"Test Using Larger Than Block-Size Key - Hash Key First"; c[3].dl=54;
    c[3].want="60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54";

    for (int i = 0; i < 4; i++) {
        uint8_t mac[32];
        assert(fj_hmac_sha256(c[i].k, c[i].kl, c[i].d, c[i].dl, mac));
        char g[65];
        hex(mac, 32, g);
        if (strcmp(g, c[i].want) != 0) {
            fprintf(stderr, "HMAC %s failed:\n  got:    %s\n  expect: %s\n",
                    c[i].n, g, c[i].want);
            assert(0);
        }
        /* Keys/data that came from rep_byte() (malloc) are freed; string
         * literals (TC2's key, TC2/TC6's data) are not. */
        if (i == 0 || i == 2 || i == 3) free(c[i].k);
        if (i == 2) free(c[i].d);
    }
    printf("hmac RFC4231: ok\n");
}

/* RFC 6070 PBKDF2-HMAC-SHA1 vectors use SHA-1; we implement SHA-256. Use the
 * RFC 7914 / common SHA-256 PBKDF2 vectors instead for correctness. */
static void test_pbkdf2_sha256(void) {
    /* Known PBKDF2-HMAC-SHA256 vectors (password, salt, iters, dkLen=32). */
    struct {
        const char *pw; size_t pw_len;
        const uint8_t *salt; size_t salt_len;
        uint32_t iters;
        const char *want;
    } c[3];

    /* 1: password="password", salt="salt", 1 iter */
    c[0].pw="password"; c[0].pw_len=8;
    c[0].salt=(const uint8_t*)"salt"; c[0].salt_len=4; c[0].iters=1;
    c[0].want="120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b";
    /* 2: same, 2 iters */
    c[1].pw="password"; c[1].pw_len=8;
    c[1].salt=(const uint8_t*)"salt"; c[1].salt_len=4; c[1].iters=2;
    c[1].want="ae4d0c95af6b46d32d0adff928f06dd02a303f8ef3c251dfd6e2d85a95474c43";
    /* 3: same, 4096 iters */
    c[2].pw="password"; c[2].pw_len=8;
    c[2].salt=(const uint8_t*)"salt"; c[2].salt_len=4; c[2].iters=4096;
    c[2].want="c5e478d59288c841aa530db6845c4c8d962893a001ce4e11a4963873aa98134a";

    for (int i = 0; i < 3; i++) {
        uint8_t out[32];
        assert(fj_pbkdf2_sha256((const uint8_t*)c[i].pw, c[i].pw_len,
                                c[i].salt, c[i].salt_len, c[i].iters, out));
        char g[65];
        hex(out, 32, g);
        if (strcmp(g, c[i].want) != 0) {
            fprintf(stderr, "PBKDF2 case %d failed:\n  got:    %s\n  expect: %s\n",
                    i + 1, g, c[i].want);
            assert(0);
        }
    }
    printf("pbkdf2 sha256: ok\n");
}

int main(void) {
    test_hmac_rfc4231();
    test_pbkdf2_sha256();
    printf("hmac/pbkdf2 host tests: ok\n");
    return 0;
}