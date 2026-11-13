#include <assert.h>
#include <stdio.h>
#include <string.h>
#include "cbor.h"
#include "hmac_request.h"

static size_t request(uint8_t *buf, size_t cap, size_t salt_len,
                      int protocol, bool duplicate, bool bad_key) {
    uint8_t x[32], y[32], salt[64], auth[16];
    memset(x, 0x11, sizeof(x)); memset(y, 0x22, sizeof(y));
    memset(salt, 0x33, sizeof(salt)); memset(auth, 0x44, sizeof(auth));
    fj_cbor_writer w; fj_cbor_writer_init(&w, buf, cap);
    fj_cbor_map(&w, 3 + (protocol != 0) + duplicate);
    fj_cbor_uint(&w, 1); fj_cbor_map(&w, 5);
    fj_cbor_uint(&w, 1); fj_cbor_uint(&w, bad_key ? 1 : 2);
    fj_cbor_uint(&w, 3); fj_cbor_neg(&w, 24);
    fj_cbor_neg(&w, 0); fj_cbor_uint(&w, 1);
    fj_cbor_neg(&w, 1); fj_cbor_bstr(&w, x, sizeof(x));
    fj_cbor_neg(&w, 2); fj_cbor_bstr(&w, y, sizeof(y));
    fj_cbor_uint(&w, 2); fj_cbor_bstr(&w, salt, salt_len);
    fj_cbor_uint(&w, 3); fj_cbor_bstr(&w, auth, sizeof(auth));
    if (protocol) { fj_cbor_uint(&w, 4); fj_cbor_uint(&w, (unsigned)protocol); }
    if (duplicate) { fj_cbor_uint(&w, 3); fj_cbor_bstr(&w, auth, sizeof(auth)); }
    assert(fj_cbor_ok(&w)); return w.len;
}
static bool parse(const uint8_t *buf, size_t len, fj_hmac_request_t *out) {
    fj_cbor_reader r; fj_cbor_item item;
    fj_cbor_reader_init(&r, buf, len);
    return fj_cbor_next(&r, &item) && fj_hmac_request_parse(&r, &item, out) && r.pos == len;
}
int main(void) {
    uint8_t buf[256]; fj_hmac_request_t out;
    size_t len = request(buf, sizeof(buf), 64, 1, false, false);
    assert(parse(buf, len, &out) && out.salt_len == 64 && out.platform_public[0] == 4);
    assert(out.platform_public[1] == 0x11 && out.platform_public[33] == 0x22);
    for (size_t i = 1; i < len; i++) assert(!parse(buf, i, &out));
    len = request(buf, sizeof(buf), 32, 0, false, false);
    assert(parse(buf, len, &out) && out.salt_len == 32);
    len = request(buf, sizeof(buf), 31, 1, false, false);
    assert(!parse(buf, len, &out));
    len = request(buf, sizeof(buf), 64, 2, false, false);
    assert(!parse(buf, len, &out));
    len = request(buf, sizeof(buf), 64, 1, true, false);
    assert(!parse(buf, len, &out));
    len = request(buf, sizeof(buf), 64, 1, false, true);
    assert(!parse(buf, len, &out));
    const uint8_t *p = (const uint8_t *)&out;
    for (size_t i = 0; i < sizeof(out); i++) assert(p[i] == 0);
    puts("hmac-secret CBOR parser tests: ok");
}
