#include "hmac_request.h"
#include "crypto.h"
#include <string.h>

static bool read_bstr(fj_cbor_reader *r, fj_cbor_item *v, uint8_t *out,
                      size_t capacity, size_t *len) {
    return v->type == FJ_CBOR_BSTR &&
           fj_cbor_read_bytes(r, v, out, capacity, len);
}

/* Parse only the COSE EC2/P-256 key agreement shape. Point validity is
 * checked by the existing P-256 ECDH implementation before key use. */
static bool parse_key(fj_cbor_reader *r, const fj_cbor_item *map,
                      uint8_t pub[65]) {
    if (map->type != FJ_CBOR_MAP || map->val > 16) return false;
    unsigned seen = 0;
    pub[0] = 4;
    for (uint64_t i = 0; i < map->val; i++) {
        fj_cbor_item k, v;
        if (!fj_cbor_next(r, &k) ||
            (k.type != FJ_CBOR_UINT && k.type != FJ_CBOR_NEG) ||
            !fj_cbor_next(r, &v)) return false;
        unsigned bit = 0;
        if (k.type == FJ_CBOR_UINT && k.val == 1) bit = 1;
        else if (k.type == FJ_CBOR_UINT && k.val == 3) bit = 2;
        else if (k.type == FJ_CBOR_NEG && k.val == 0) bit = 4;
        else if (k.type == FJ_CBOR_NEG && k.val == 1) bit = 8;
        else if (k.type == FJ_CBOR_NEG && k.val == 2) bit = 16;
        else { if (!fj_cbor_skip(r, &v)) return false; continue; }
        if (seen & bit) return false;
        seen |= bit;
        size_t n = 0;
        if (bit == 1 && (v.type != FJ_CBOR_UINT || v.val != 2)) return false;
        if (bit == 2 && (v.type != FJ_CBOR_NEG || v.val != 24)) return false;
        if (bit == 4 && (v.type != FJ_CBOR_UINT || v.val != 1)) return false;
        if (bit == 8 && (!read_bstr(r, &v, pub + 1, 32, &n) || n != 32)) return false;
        if (bit == 16 && (!read_bstr(r, &v, pub + 33, 32, &n) || n != 32)) return false;
    }
    return seen == 31;
}

bool fj_hmac_request_parse(fj_cbor_reader *r, const fj_cbor_item *map,
                           fj_hmac_request_t *out) {
    if (!out) return false;
    fj_hmac_request_t temp = {0};
    bool ok = false;
    unsigned seen = 0;
    if (!r || !map || map->type != FJ_CBOR_MAP || map->val > 8) goto done;
    for (uint64_t i = 0; i < map->val; i++) {
        fj_cbor_item k, v;
        if (!fj_cbor_next(r, &k) || k.type != FJ_CBOR_UINT ||
            !fj_cbor_next(r, &v)) goto done;
        if (k.val < 1 || k.val > 4) goto done;
        unsigned bit = 1u << (k.val - 1);
        if (seen & bit) goto done;
        seen |= bit;
        size_t n = 0;
        switch (k.val) {
        case 1: if (!parse_key(r, &v, temp.platform_public)) goto done; break;
        case 2:
            if (!read_bstr(r, &v, temp.salt_enc, sizeof(temp.salt_enc), &n) ||
                (n != 32 && n != 64)) goto done;
            temp.salt_len = n;
            break;
        case 3:
            if (!read_bstr(r, &v, temp.salt_auth, sizeof(temp.salt_auth), &n) || n != 16) goto done;
            break;
        case 4: if (v.type != FJ_CBOR_UINT || v.val != 1) goto done; break;
        }
    }
    if ((seen & 7u) != 7u) goto done;
    *out = temp;
    ok = true;
done:
    if (!ok) memset(out, 0, sizeof(*out));
    fj_secure_zero(&temp, sizeof(temp));
    return ok;
}
