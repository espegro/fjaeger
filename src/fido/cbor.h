/*
 * Fjaeger - minimal CBOR encoder / decoder for CTAP2.
 *
 * Supports the subset of RFC 7049 needed by CTAP2 / WebAuthn:
 *   - unsigned integers (major 0)
 *   - negative integers (major 1)
 *   - byte strings (major 2)
 *   - text strings (major 3)
 *   - arrays (major 4)
 *   - maps (major 5)
 *   - booleans / null (major 7, simple values)
 */
#ifndef FJAEGER_CBOR_H
#define FJAEGER_CBOR_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ------------------------------------------------------------------ */
/* Encoder                                                            */
/* ------------------------------------------------------------------ */

/* Growable byte buffer used by the encoder. */
typedef struct {
    uint8_t *buf;
    size_t   cap;
    size_t   len;
} fj_cbor_writer;

/* Initialise a writer over an external buffer of 'cap' bytes. */
void fj_cbor_writer_init(fj_cbor_writer *w, uint8_t *buf, size_t cap);

/* Whether the writer is still within capacity (all appends no-oped on
 * overflow; the final length is clamped). */
bool fj_cbor_ok(const fj_cbor_writer *w);

void fj_cbor_uint(fj_cbor_writer *w, uint64_t v);
void fj_cbor_neg(fj_cbor_writer *w, uint64_t magnitude); /* encodes -1-magnitude */
void fj_cbor_bstr(fj_cbor_writer *w, const uint8_t *data, size_t len);
void fj_cbor_tstr(fj_cbor_writer *w, const char *s);
void fj_cbor_array(fj_cbor_writer *w, size_t n);
void fj_cbor_map(fj_cbor_writer *w, size_t n);
void fj_cbor_bool(fj_cbor_writer *w, bool v);
void fj_cbor_null(fj_cbor_writer *w);

/* ------------------------------------------------------------------ */
/* Decoder                                                            */
/* ------------------------------------------------------------------ */

typedef struct {
    const uint8_t *buf;
    size_t         len;
    size_t         pos;
} fj_cbor_reader;

/* Tags of a decoded item. */
typedef enum {
    FJ_CBOR_UINT = 0,
    FJ_CBOR_NEG  = 1,
    FJ_CBOR_BSTR = 2,
    FJ_CBOR_TSTR = 3,
    FJ_CBOR_ARRAY= 4,
    FJ_CBOR_MAP  = 5,
    FJ_CBOR_BOOL = 7,   /* sub-type 20/21 */
    FJ_CBOR_NULL = 8,
    FJ_CBOR_INVALID = 0xff,
} fj_cbor_type;

/* Result of decoding one head. 'val' carries the length for array/map,
 * the integer for uint/neg, the byte length for bstr/tstr. */
typedef struct {
    fj_cbor_type type;
    uint64_t     val;
    size_t       start;  /* offset of the item's value payload */
} fj_cbor_item;

void fj_cbor_reader_init(fj_cbor_reader *r, const uint8_t *buf, size_t len);

/* Decode the item head at the current position. On success advances pos
 * past the head (not the payload). */
bool fj_cbor_next(fj_cbor_reader *r, fj_cbor_item *it);

/* For bstr/tstr: copy the payload, advancing past it. Returns true on
 * success. */
bool fj_cbor_read_bytes(fj_cbor_reader *r, fj_cbor_item *it,
                        uint8_t *out, size_t max, size_t *out_len);

/* Skip the full payload of the current item (used to skip unparsed map
 * values). The item must have been produced by fj_cbor_next. */
bool fj_cbor_skip(fj_cbor_reader *r, fj_cbor_item *it);

#ifdef __cplusplus
}
#endif

#endif /* FJAEGER_CBOR_H */