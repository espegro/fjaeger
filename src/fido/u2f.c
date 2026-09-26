/*
 * Fjaeger - U2F (CTAP1) authenticator over HID.
 */
#include <string.h>
#include "u2f.h"
#include "ctap2.h"
#include "keys.h"
#include "state.h"
#include "tusb.h"

/* ------------------------------------------------------------------ */
/* U2FHID frame / command constants                                    */
/* ------------------------------------------------------------------ */
#define U2FHID_FRAME_LEN  64
#define U2FHID_HEADER_LEN 7
#define U2FHID_INIT_DATA  (U2FHID_FRAME_LEN - U2FHID_HEADER_LEN)  /* 57 */
#define U2FHID_CONT_DATA  (U2FHID_FRAME_LEN - 5)                  /* 59 */

#define TYPE_MASK  0x80
#define TYPE_INIT  0x80
#define TYPE_CONT  0x00

/* Command numbers without the initial-frame bit. */
#define U2FHID_PING  0x01
#define U2FHID_MSG   0x03
#define U2FHID_LOCK  0x04
#define U2FHID_INIT  0x06
#define U2FHID_WINK  0x08
#define U2FHID_CBOR  0x10
#define U2FHID_SYNC  0x3C
#define U2FHID_ERROR 0x3F

#define ERR_NONE            0x00
#define ERR_INVALID_CMD     0x01
#define ERR_INVALID_PAR     0x02
#define ERR_INVALID_LEN     0x03
#define ERR_INVALID_SEQ     0x04
#define ERR_MSG_TIMEOUT     0x05
#define ERR_CHANNEL_BUSY    0x06
#define ERR_LOCK_BUSY       0x07
#define ERR_CHANNEL_INVALID 0x08

/* U2F APDU instructions */
#define U2F_CLA     0x00
#define U2F_REGISTER    0x01
#define U2F_AUTHENTICATE 0x02
#define U2F_VERSION     0x03

/* U2F status words */
#define SW_NO_ERROR             0x9000
#define SW_WRONG_DATA           0x6A80
#define SW_INS_NOT_SUPPORTED    0x6D00
#define SW_CONDITIONS_NOT_SAT   0x6985

/* ------------------------------------------------------------------ */
/* Inbound message assembly                                            */
/* ------------------------------------------------------------------ */
typedef struct {
    uint32_t cid;
    uint8_t  cmd;
    uint16_t len;
    uint16_t seq;      /* next expected continuation sequence number */
    uint16_t pos;      /* bytes received so far */
    uint8_t  buf[1200];
} rx_t;

static rx_t rx;
static bool rx_active = false;

/* Outbound reports */
typedef struct {
    uint8_t frame[U2FHID_FRAME_LEN];
    uint16_t frame_len;
} out_frame_t;

#define OUT_QUEUE 32
static out_frame_t out_q[OUT_QUEUE];
static uint8_t out_head = 0, out_tail = 0;
static bool out_pending = false;

/* CTAP2 crypto is stack-intensive on the RP2350.  Keep the transport reply
 * workspace in BSS; dispatch is synchronous, so it is never re-entered. */
static uint8_t cbor_response[512];

/* ------------------------------------------------------------------ */
/* Small helpers                                                       */
/* ------------------------------------------------------------------ */
static void be32(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)(v);
}

static uint32_t rd_be32(const uint8_t *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

static void queue_frame(const uint8_t *data, uint16_t len) {
    if ((out_tail + 1) % OUT_QUEUE == out_head) return; /* queue full */

    out_frame_t *f = &out_q[out_tail];
    uint16_t n = len < U2FHID_FRAME_LEN ? len : U2FHID_FRAME_LEN;
    memcpy(f->frame, data, n);
    f->frame_len = n;
    out_tail = (out_tail + 1) % OUT_QUEUE;
    out_pending = true;
}

/* Send an error report for the given channel. */
static void send_error(uint32_t cid, uint8_t err) {
    uint8_t frame[U2FHID_FRAME_LEN];
    memset(frame, 0, sizeof(frame));
    frame[0] = (uint8_t)(cid >> 24);
    frame[1] = (uint8_t)(cid >> 16);
    frame[2] = (uint8_t)(cid >> 8);
    frame[3] = (uint8_t)(cid);
    frame[4] = U2FHID_ERROR;
    frame[5] = 0;
    frame[6] = 1;
    frame[7] = err;
    queue_frame(frame, U2FHID_FRAME_LEN);
}

/* ------------------------------------------------------------------ */
/* Outbound HID message splitting                                      */
/* ------------------------------------------------------------------ */
static void send_hid(uint32_t cid, uint8_t cmd, const uint8_t *payload, uint16_t len) {
    uint8_t frame[U2FHID_FRAME_LEN];
    uint16_t pos = 0;

    /* INIT frame */
    memset(frame, 0, sizeof(frame));
    frame[0] = (uint8_t)(cid >> 24);
    frame[1] = (uint8_t)(cid >> 16);
    frame[2] = (uint8_t)(cid >> 8);
    frame[3] = (uint8_t)(cid);
    frame[4] = (uint8_t)(cmd | TYPE_INIT);
    frame[5] = (uint8_t)(len >> 8);
    frame[6] = (uint8_t)(len);
    uint16_t n = len < U2FHID_INIT_DATA ? len : U2FHID_INIT_DATA;
    if (n) memcpy(frame + U2FHID_HEADER_LEN, payload, n);
    queue_frame(frame, U2FHID_FRAME_LEN);
    pos = n;

    /* CONTINUATION frames */
    uint8_t seq = 0;
    while (pos < len) {
        memset(frame, 0, sizeof(frame));
        frame[0] = (uint8_t)(cid >> 24);
        frame[1] = (uint8_t)(cid >> 16);
        frame[2] = (uint8_t)(cid >> 8);
        frame[3] = (uint8_t)(cid);
        frame[4] = (uint8_t)(seq & 0x7f);
        n = (len - pos) < U2FHID_CONT_DATA ? (len - pos) : U2FHID_CONT_DATA;
        memcpy(frame + 5, payload + pos, n);
        queue_frame(frame, U2FHID_FRAME_LEN);
        pos += n;
        seq++;
    }
}

void fj_u2f_init(void) {
    rx_active = false;
    memset(&rx, 0, sizeof(rx));
    out_head = out_tail = 0;
    out_pending = false;
}

bool fj_u2f_ready(void) {
    return out_pending;
}

bool fj_u2f_pop_report(uint8_t out[64]) {
    if (!out_pending) return false;
    if (out_head == out_tail) {
        out_pending = false;
        return false;
    }
    out_frame_t *f = &out_q[out_head];
    memcpy(out, f->frame, f->frame_len);
    if (f->frame_len < U2FHID_FRAME_LEN) memset(out + f->frame_len, 0, U2FHID_FRAME_LEN - f->frame_len);
    out_head = (out_head + 1) % OUT_QUEUE;
    out_pending = (out_head != out_tail);
    return true;
}

/* ------------------------------------------------------------------ */
/* CTAP1 compatibility probe                                           */
/* ------------------------------------------------------------------ */

static void send_apdu_status(uint32_t cid, uint16_t status) {
    uint8_t resp[2] = {
        (uint8_t)(status >> 8),
        (uint8_t)status,
    };
    send_hid(cid, U2FHID_MSG, resp, sizeof(resp));
}

/* OpenSSH/libfido2 uses a CTAP1 REGISTER APDU only to select a token by
 * user presence before reopening it for the actual CTAP2 operation.  Fjaeger
 * treats an unlocked device as user presence and returns only the APDU status
 * word expected by that probe.  No credential is created here: full CTAP1
 * registration/authentication remains intentionally unsupported. */
static void handle_msg(uint32_t cid, const uint8_t *p, uint16_t len) {
    if (len < 4 || p[0] != U2F_CLA) {
        send_apdu_status(cid, SW_WRONG_DATA);
        return;
    }

    if (p[1] == U2F_VERSION) {
        static const uint8_t response[] = {
            'U', '2', 'F', '_', 'V', '2',
            (uint8_t)(SW_NO_ERROR >> 8), (uint8_t)SW_NO_ERROR,
        };
        send_hid(cid, U2FHID_MSG, response, sizeof(response));
        return;
    }

    if (p[1] != U2F_REGISTER) {
        send_apdu_status(cid, SW_INS_NOT_SUPPORTED);
        return;
    }

    /* libfido2 sends an extended-length APDU:
     * CLA INS P1 P2 00 LcHi LcLo challenge[32] application[32] LeHi LeLo */
    if (len < 7 || p[4] != 0) {
        send_apdu_status(cid, SW_WRONG_DATA);
        return;
    }
    uint16_t data_len = ((uint16_t)p[5] << 8) | p[6];
    if (data_len != 64 || len < (uint16_t)(7 + data_len)) {
        send_apdu_status(cid, SW_WRONG_DATA);
        return;
    }

    send_apdu_status(cid, fj_state_get() == FJ_STATE_UNLOCKED
                              ? SW_NO_ERROR
                              : SW_CONDITIONS_NOT_SAT);
}

static void handle_init(uint32_t cid) {
    uint8_t resp[17];
    uint32_t new_cid = cid;

    if (rx.len != 8) {
        send_error(cid, ERR_INVALID_LEN);
        return;
    }

    /* A broadcast INIT allocates a channel. INIT on an allocated channel is
     * a resynchronisation request and keeps that channel. */
    if (cid == 0xffffffffu) {
        do {
            fj_random(&new_cid, sizeof(new_cid));
        } while (new_cid == 0 || new_cid == 0xffffffffu);
    }

    memcpy(resp, rx.buf, 8);       /* nonce */
    be32(resp + 8, new_cid);       /* allocated channel */
    resp[12] = 2;                  /* CTAPHID protocol version */
    resp[13] = 1;                  /* device major */
    resp[14] = 0;                  /* device minor */
    resp[15] = 0;                  /* device build */
    resp[16] = 0x04;               /* CBOR; MSG accepted for touch probe */
    send_hid(cid, U2FHID_INIT, resp, sizeof(resp));
}

static void handle_ping(uint32_t cid, const uint8_t *payload, uint16_t len) {
    send_hid(cid, U2FHID_PING, payload, len);
}

/* Handle a CTAP2 CBOR message carried in a U2FHID CBOR (0x10) message. */
static void handle_cbor(uint32_t cid, const uint8_t *payload, uint16_t len) {
    size_t rlen = fj_ctap2_dispatch(payload, len, cbor_response,
                                    sizeof(cbor_response));
    if (rlen == 0) {
        send_error(cid, ERR_INVALID_PAR);
        return;
    }
    send_hid(cid, U2FHID_CBOR, cbor_response, (uint16_t)rlen);
}

/* Process a complete assembled inbound message. */
static void process_rx(void) {
    uint32_t cid = rx.cid;
    uint8_t cmd = rx.cmd & ~TYPE_MASK;
    uint16_t len = rx.len;

    switch (cmd) {
        case U2FHID_INIT: handle_init(cid); break;
        case U2FHID_PING: handle_ping(cid, rx.buf, len); break;
        case U2FHID_MSG:  handle_msg(cid, rx.buf, len); break;
        case U2FHID_CBOR: handle_cbor(cid, rx.buf, len); break;
        case U2FHID_SYNC:
            send_error(cid, ERR_NONE);
            break;
        case U2FHID_LOCK:
        case U2FHID_WINK:
            send_error(cid, ERR_INVALID_CMD);
            break;
        default:
            send_error(cid, ERR_INVALID_CMD);
            break;
    }
}

/* ------------------------------------------------------------------ */
/* Inbound frame handling                                              */
/* ------------------------------------------------------------------ */
void fj_u2f_hid_rx(const uint8_t *report, size_t len) {
    if (len < U2FHID_FRAME_LEN) return;

    uint32_t cid = rd_be32(report);
    uint8_t cmd = report[4];

    if (cmd & TYPE_INIT) {
        /* New message. */
        rx.cid = cid;
        rx.cmd = report[4];
        rx.len = ((uint16_t)report[5] << 8) | report[6];
        rx.seq = 0;
        rx.pos = 0;

        if (rx.len > sizeof(rx.buf)) {
            send_error(cid, ERR_INVALID_LEN);
            rx_active = false;
            return;
        }
        uint16_t n = rx.len < U2FHID_INIT_DATA ? rx.len : U2FHID_INIT_DATA;
        memcpy(rx.buf, report + U2FHID_HEADER_LEN, n);
        rx.pos = n;
        rx_active = true;

        if (rx.pos >= rx.len) {
            process_rx();
            rx_active = false;
        }
    } else if (rx_active && cid == rx.cid) {
        /* Continuation frame. */
        uint8_t seq = cmd & 0x7f;
        if (seq != (uint8_t)rx.seq) {
            send_error(cid, ERR_INVALID_SEQ);
            rx_active = false;
            return;
        }
        uint16_t rem = rx.len - rx.pos;
        uint16_t n = rem < U2FHID_CONT_DATA ? rem : U2FHID_CONT_DATA;
        memcpy(rx.buf + rx.pos, report + 5, n);
        rx.pos += n;
        rx.seq++;

        if (rx.pos >= rx.len) {
            process_rx();
            rx_active = false;
        }
    } else {
        send_error(cid, ERR_INVALID_SEQ);
    }
}

void fj_u2f_task(void) {
    if (!out_pending || !tud_hid_ready()) return;

    uint8_t report[U2FHID_FRAME_LEN];
    if (fj_u2f_pop_report(report))
        (void)tud_hid_n_report(0, 0, report, sizeof(report));
}
