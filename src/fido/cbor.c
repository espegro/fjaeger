/*
 * Fjaeger - minimal CBOR encoder / decoder (see cbor.h).
 */
#include <string.h>

#include "cbor.h"

/* ------------------------------------------------------------------ */
/* Helpers                                                             */
/* ------------------------------------------------------------------ */
static inline void put_u8(uint8_t *p, uint8_t v) { p[0] = v; }

static void put_head(fj_cbor_writer *w, uint8_t major, uint64_t v) {
    if (!w || w->len + 1 > w->cap) { if (w) w->len = w->cap; return; }
    uint8_t m = (uint8_t)(major << 5);
    if (v < 24) {
        put_u8(w->buf + w->len, (uint8_t)(m | v));
        w->len += 1;
    } else if (v <= 0xff) {
        if (w->len + 2 > w->cap) { w->len = w->cap; return; }
        put_u8(w->buf + w->len, (uint8_t)(m | 24));
        put_u8(w->buf + w->len + 1, (uint8_t)v);
        w->len += 2;
    } else if (v <= 0xffff) {
        if (w->len + 3 > w->cap) { w->len = w->cap; return; }
        put_u8(w->buf + w->len, (uint8_t)(m | 25));
        w->buf[w->len + 1] = (uint8_t)(v >> 8);
        w->buf[w->len + 2] = (uint8_t)(v);
        w->len += 3;
    } else if (v <= 0xffffffffu) {
        if (w->len + 5 > w->cap) { w->len = w->cap; return; }
        put_u8(w->buf + w->len, (uint8_t)(m | 26));
        w->buf[w->len + 1] = (uint8_t)(v >> 24);
        w->buf[w->len + 2] = (uint8_t)(v >> 16);
        w->buf[w->len + 3] = (uint8_t)(v >> 8);
        w->buf[w->len + 4] = (uint8_t)(v);
        w->len += 5;
    } else {
        if (w->len + 9 > w->cap) { w->len = w->cap; return; }
        put_u8(w->buf + w->len, (uint8_t)(m | 27));
        for (int i = 0; i < 8; i++)
            w->buf[w->len + 1 + i] = (uint8_t)(v >> (56 - 8 * i));
        w->len += 9;
    }
}

void fj_cbor_writer_init(fj_cbor_writer *w, uint8_t *buf, size_t cap) {
    w->buf = buf;
    w->cap = cap;
    w->len = 0;
}

bool fj_cbor_ok(const fj_cbor_writer *w) {
    return w->len < w->cap;
}

/* ------------------------------------------------------------------ */
/* Encoder API                                                         */
/* ------------------------------------------------------------------ */
void fj_cbor_uint(fj_cbor_writer *w, uint64_t v) { put_head(w, 0, v); }

void fj_cbor_neg(fj_cbor_writer *w, uint64_t magnitude) { put_head(w, 1, magnitude); }

void fj_cbor_bstr(fj_cbor_writer *w, const uint8_t *data, size_t len) {
    put_head(w, 2, len);
    if (w->len + len <= w->cap) {
        if (len) memcpy(w->buf + w->len, data, len);
        w->len += len;
    } else {
        w->len = w->cap;
    }
}

void fj_cbor_tstr(fj_cbor_writer *w, const char *s) {
    size_t len = s ? strlen(s) : 0;
    put_head(w, 3, len);
    if (w->len + len <= w->cap) {
        if (len) memcpy(w->buf + w->len, s, len);
        w->len += len;
    } else {
        w->len = w->cap;
    }
}

void fj_cbor_array(fj_cbor_writer *w, size_t n) { put_head(w, 4, n); }

void fj_cbor_map(fj_cbor_writer *w, size_t n) { put_head(w, 5, n); }

void fj_cbor_bool(fj_cbor_writer *w, bool v) {
    if (w->len + 1 > w->cap) { w->len = w->cap; return; }
    w->buf[w->len++] = (uint8_t)(0xf4 | (v ? 1 : 0));
}

void fj_cbor_null(fj_cbor_writer *w) {
    if (w->len + 1 > w->cap) { w->len = w->cap; return; }
    w->buf[w->len++] = 0xf6;
}

/* ------------------------------------------------------------------ */
/* Decoder                                                             */
/* ------------------------------------------------------------------ */
void fj_cbor_reader_init(fj_cbor_reader *r, const uint8_t *buf, size_t len) {
    r->buf = buf;
    r->len = len;
    r->pos = 0;
}

static uint64_t read_uint_raw(const uint8_t *p, size_t n) {
    uint64_t v = 0;
    for (size_t i = 0; i < n; i++) v = (v << 8) | p[i];
    return v;
}

bool fj_cbor_next(fj_cbor_reader *r, fj_cbor_item *it) {
    if (!r || !it || r->pos >= r->len) return false;

    uint8_t ib = r->buf[r->pos];
    uint8_t major = (uint8_t)(ib >> 5);
    uint8_t info = (uint8_t)(ib & 0x1f);
    it->type = FJ_CBOR_INVALID;
    it->start = r->pos + 1;

    uint64_t arg = 0;
    size_t extra = 0;

    /* Simple values (major 7) are handled inline. */
    if (major == 7) {
        switch (info) {
            case 20: it->type = FJ_CBOR_BOOL; it->val = 0; r->pos += 1; return true;
            case 21: it->type = FJ_CBOR_BOOL; it->val = 1; r->pos += 1; return true;
            case 22: it->type = FJ_CBOR_NULL; it->val = 0; r->pos += 1; return true;
            default: return false;
        }
    }

    switch (info) {
        case 24: extra = 1; break;
        case 25: extra = 2; break;
        case 26: extra = 4; break;
        case 27: extra = 8; break;
        default:
            if (info < 24) {
                arg = info;
            } else {
                return false; /* indefinite-length not supported */
            }
            break;
    }

    if (extra) {
        if (r->pos + 1 + extra > r->len) return false;
        arg = read_uint_raw(r->buf + r->pos + 1, extra);
    }

    r->pos += 1 + extra;
    it->start = r->pos;

    switch (major) {
        case 0: it->type = FJ_CBOR_UINT;  it->val = arg; break;
        case 1: it->type = FJ_CBOR_NEG;   it->val = arg; break;
        case 2: it->type = FJ_CBOR_BSTR;  it->val = arg; break;
        case 3: it->type = FJ_CBOR_TSTR;  it->val = arg; break;
        case 4: it->type = FJ_CBOR_ARRAY; it->val = arg; break;
        case 5: it->type = FJ_CBOR_MAP;   it->val = arg; break;
        default: return false;
    }
    return true;
}

bool fj_cbor_read_bytes(fj_cbor_reader *r, fj_cbor_item *it,
                        uint8_t *out, size_t max, size_t *out_len) {
    if (it->type != FJ_CBOR_BSTR && it->type != FJ_CBOR_TSTR) return false;
    if (it->val > max) return false;
    if (r->pos + it->val > r->len) return false;
    if (it->val) memcpy(out, r->buf + r->pos, (size_t)it->val);
    if (out_len) *out_len = (size_t)it->val;
    r->pos += (size_t)it->val;
    return true;
}

bool fj_cbor_skip(fj_cbor_reader *r, fj_cbor_item *it) {
    size_t count;
    switch (it->type) {
        case FJ_CBOR_UINT:
        case FJ_CBOR_NEG:
            return true; /* no payload */
        case FJ_CBOR_BSTR:
        case FJ_CBOR_TSTR: {
            if (r->pos + it->val > r->len) return false;
            r->pos += (size_t)it->val;
            return true;
        }
        case FJ_CBOR_ARRAY:
            count = (size_t)it->val;
            for (size_t i = 0; i < count; i++) {
                fj_cbor_item child;
                if (!fj_cbor_next(r, &child)) return false;
                if (!fj_cbor_skip(r, &child)) return false;
            }
            return true;
        case FJ_CBOR_MAP:
            count = (size_t)it->val;
            for (size_t i = 0; i < 2 * count; i++) {
                fj_cbor_item child;
                if (!fj_cbor_next(r, &child)) return false;
                if (!fj_cbor_skip(r, &child)) return false;
            }
            return true;
        case FJ_CBOR_BOOL:
        case FJ_CBOR_NULL:
            return true;
        default:
            return false;
    }
}