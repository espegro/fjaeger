/* Fuzz the CBOR reader / parser (FJ-N009). Deep-walks whatever valid items
 * it can; malformed / truncated input must be rejected, never crash. */
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "cbor.h"

#define FZ_CAP 2048u

static bool fz_walk(fj_cbor_reader *r);

static bool fz_consume(fj_cbor_item *it, fj_cbor_reader *r) {
    switch (it->type) {
    case FJ_CBOR_BSTR:
    case FJ_CBOR_TSTR: {
        uint8_t tmp[64];
        size_t n = 0;
        return fj_cbor_read_bytes(r, it, tmp, sizeof(tmp), &n);
    }
    case FJ_CBOR_ARRAY: {
        uint32_t i, n = it->val < 256u ? (uint32_t)it->val : 256u;
        for (i = 0; i < n; i++) if (!fz_walk(r)) return false;
        return true;
    }
    case FJ_CBOR_MAP: {
        uint32_t i, n = it->val < 256u ? (uint32_t)it->val : 256u;
        for (i = 0; i < n; i++) {          /* key + value */
            if (!fz_walk(r)) return false;
            if (!fz_walk(r)) return false;
        }
        return true;
    }
    default:
        return true; /* scalar: no payload */
    }
}

static bool fz_walk(fj_cbor_reader *r) {
    fj_cbor_item it;
    if (!fj_cbor_next(r, &it)) return true;   /* EOF/truncated: stop cleanly */
    return fz_consume(&it, r);
}

int fz_cbor(const uint8_t *data, size_t size) {
    if (size > FZ_CAP) size = FZ_CAP;
    fj_cbor_reader r;
    fj_cbor_reader_init(&r, data, size);
    while (r.pos < r.len) {
        fj_cbor_item it;
        if (!fj_cbor_next(&r, &it)) break;
        if (!fz_consume(&it, &r)) break;
    }
    return 0;
}

/* libFuzzer entry point (built with -fsanitize=fuzzer). */
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    return fz_cbor(data, size);
}
