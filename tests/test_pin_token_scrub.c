/* Include production code to inspect its private token storage.
 * Crypto/state dependencies are stubbed by fuzz/stubs.c. */
#include <assert.h>
#include <stdio.h>
#include "crypto.h"
static unsigned wipes16, wipes32;
static void tracked_zero(void *ptr, size_t len) {
    fj_secure_zero(ptr,len);
    if (len==16) wipes16++;
    if (len==32) wipes32++;
    for (size_t i=0;i<len;i++) assert(((uint8_t *)ptr)[i]==0);
}
#define fj_secure_zero tracked_zero
#include "../src/fido/pin.c"
#undef fj_secure_zero

static unsigned fault;
bool __wrap_fj_ecdh_shared_secret(const uint8_t *key, const uint8_t *pub, uint8_t *out) {
    (void)key; (void)pub; memset(out,0xaa,32); return fault!=1;
}
bool __wrap_fj_aes_cbc(const uint8_t *key, const uint8_t *iv, uint8_t *buf, size_t len, bool enc) {
    (void)key; (void)iv; (void)buf; (void)len;
    return fault!=(enc ? 4u : 2u);
}
bool __wrap_fj_state_ctap2_verify(const uint8_t *verifier) {
    (void)verifier; return fault!=3;
}

static void test_pin_cleanup(void) {
    uint8_t req[256], out[256], coordinate[32]={1}, hash[16]={2};
    fj_cbor_writer w;
    fj_cbor_writer_init(&w,req,sizeof(req));
    fj_cbor_map(&w,4);
    fj_cbor_uint(&w,1); fj_cbor_uint(&w,1);
    fj_cbor_uint(&w,2); fj_cbor_uint(&w,5);
    fj_cbor_uint(&w,3); fj_cbor_map(&w,3);
    fj_cbor_neg(&w,0); fj_cbor_uint(&w,1);
    fj_cbor_neg(&w,1); fj_cbor_bstr(&w,coordinate,32);
    fj_cbor_neg(&w,2); fj_cbor_bstr(&w,coordinate,32);
    fj_cbor_uint(&w,6); fj_cbor_bstr(&w,hash,16);
    assert(fj_cbor_ok(&w));
    for (fault=0;fault<=5;fault++) {
        fj_pin_reset_token();
        wipes16=wipes32=0;
        size_t len=fj_ctap2_client_pin(req,w.len,out,fault==5 ? 2 : sizeof(out));
        assert(wipes16==1);
        /* ECDH intermediate, shared secret, token copy, plus newly minted
         * global token when encryption/response construction fails. */
        assert(wipes32==((fault==4 || fault==5) ? 4u : 3u));
        if (fault==0) assert(len>1 && out[0]==0 && token_valid);
        else {
            assert(!token_valid);
            assert(len==0 || out[0]!=0);
            for (size_t i=0;i<sizeof(pin_token);i++) assert(pin_token[i]==0);
        }
    }
}

int main(void) {
    test_pin_cleanup();
    for (unsigned cycle = 0; cycle < 2; cycle++) {
        fj_pin_init();
        assert(token_valid);
        uint8_t nonzero = 0;
        for (size_t i = 0; i < sizeof(pin_token); i++) nonzero |= pin_token[i];
        assert(nonzero);
        fj_pin_reset_token();
        assert(!token_valid);
        for (size_t i = 0; i < sizeof(pin_token); i++) assert(pin_token[i] == 0);
        uint8_t param[16] = {0};
        assert(!fj_pin_verify_auth(NULL, 0, param));
    }
    puts("production pin_token secure-zero test: ok");
}
