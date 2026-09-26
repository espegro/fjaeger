/*
 * Fjaeger - U2F (CTAP1) authenticator over HID.
 */
#include <string.h>
#include <stdio.h>

#include "u2f.h"
#include "ctap2.h"
#include "crypto.h"
#include "keys.h"
#include "state.h"

#include "mbedtls/ecp.h"
#include "mbedtls/bignum.h"
#include "mbedtls/pk.h"

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

#define U2FHID_PING  0x81
#define U2FHID_MSG   0x83
#define U2FHID_LOCK  0x84
#define U2FHID_INIT  0x86
#define U2FHID_WINK  0x88
#define U2FHID_SYNC  0xBC
#define U2FHID_CBOR  0x10
#define U2FHID_ERROR 0xBF

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

/* U2F AUTHENTICATE controls */
#define U2F_AUTH_CHECK_ONLY    0x07
#define U2F_AUTH_ENFORCE_UP    0x03
#define U2F_AUTH_DONT_ENFORCE  0x08

/* Counter persisted in a reserved byte of each slot key material; for this
 * prototype we keep a simple volatile counter seeded at boot. */
static uint32_t u2f_counter = 0;

/* ------------------------------------------------------------------ */
/* Inbound message assembly                                            */
/* ------------------------------------------------------------------ */
typedef struct {
    uint32_t cid;
    uint8_t  cmd;
    uint16_t len;
    uint16_t seq;      /* next expected continuation sequence number */
    uint16_t pos;      /* bytes received so far */
    uint8_t  buf[U2FHID_INIT_DATA + 4 * U2FHID_CONT_DATA];
} rx_t;

static rx_t rx;
static bool rx_active = false;

/* Outbound reports */
typedef struct {
    uint8_t frame[U2FHID_FRAME_LEN];
    uint16_t frame_len;
} out_frame_t;

#define OUT_QUEUE 8
static out_frame_t out_q[OUT_QUEUE];
static uint8_t out_head = 0, out_tail = 0;
static bool out_pending = false;

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
/* U2F operation handling                                              */
/* ------------------------------------------------------------------ */

/* Build and sign the U2F_AUTHENTICATE signature over
 *   user_presence(1) || counter(4) || challenge(32) || app(32)
 * with the active slot key. */
static bool auth_sign(const uint8_t app[32], const uint8_t challenge[32],
                      const uint8_t *priv, uint8_t sig[64]) {
    uint8_t data[1 + 4 + 32 + 32];
    uint8_t digest[FJ_HASH_LEN];

    data[0] = 0x01;               /* user presence */
    be32(data + 1, u2f_counter);  /* counter */
    memcpy(data + 5, challenge, 32);
    memcpy(data + 37, app, 32);

    fj_sha256(data, sizeof(data), digest);
    return fj_ecdsa_sign(priv, digest, sig);
}

/* Derive the uncompressed 65-byte P-256 public key (0x04 || X || Y)
 * from a 32-byte private scalar. */
static bool derive_pubkey(const uint8_t priv[32], uint8_t pub[65]) {
    mbedtls_ecp_group grp;
    mbedtls_mpi d;
    mbedtls_ecp_point q;
    int ret;

    mbedtls_ecp_group_init(&grp);
    mbedtls_mpi_init(&d);
    mbedtls_ecp_point_init(&q);

    if ((ret = mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_SECP256R1)) != 0) goto fail;
    if ((ret = mbedtls_mpi_read_binary(&d, priv, 32)) != 0) goto fail;
    if ((ret = mbedtls_ecp_mul(&grp, &q, &d, &grp.G, NULL, NULL)) != 0) goto fail;

    size_t olen = 0;
    if ((ret = mbedtls_ecp_point_write_binary(&grp, &q, MBEDTLS_ECP_PF_UNCOMPRESSED,
                                              &olen, pub, 65)) != 0) goto fail;

    mbedtls_ecp_point_free(&q);
    mbedtls_mpi_free(&d);
    mbedtls_ecp_group_free(&grp);
    return olen == 65;

fail:
    mbedtls_ecp_point_free(&q);
    mbedtls_mpi_free(&d);
    mbedtls_ecp_group_free(&grp);
    (void)ret;
    return false;
}

/* Handle a U2F APDU carried inside a U2FHID MSG. */
static void handle_apdu(uint32_t cid, const uint8_t *p, uint16_t len) {
    uint8_t resp[300];
    uint16_t rlen = 0;

    if (len < 4) { send_error(cid, ERR_INVALID_LEN); return; }
    if (p[0] != U2F_CLA) { send_error(cid, ERR_INVALID_PAR); return; }

    uint8_t ins = p[1];
    uint16_t data_len = ((uint16_t)p[4] << 8) | p[5];
    const uint8_t *data = p + 7;

    if (len < (uint16_t)(7 + data_len)) { send_error(cid, ERR_INVALID_LEN); return; }

    switch (ins) {
        case U2F_VERSION: {
            const char *ver = "U2F_V2";
            resp[rlen++] = (uint8_t)strlen(ver);
            memcpy(resp + rlen, ver, strlen(ver));
            rlen += (uint16_t)strlen(ver);
            resp[rlen++] = (uint8_t)(SW_NO_ERROR >> 8);
            resp[rlen++] = (uint8_t)(SW_NO_ERROR);
            break;
        }

        case U2F_AUTHENTICATE: {
            uint8_t control = data[0];
            const uint8_t *app = data + 1;
            const uint8_t *challenge = data + 33;
            uint8_t kh_len = data[65];
            const uint8_t *kh = data + 66;

            (void)kh_len; (void)kh;

            const fj_slot_t *slot = fj_keys_get(fj_keys_active_slot());
            if (!slot) {
                resp[rlen++] = (uint8_t)(SW_WRONG_DATA >> 8);
                resp[rlen++] = (uint8_t)(SW_WRONG_DATA);
                break;
            }
            if (fj_state_get() != FJ_STATE_UNLOCKED) {
                /* User presence not satisfied -> require unlock first. */
                resp[rlen++] = (uint8_t)(SW_CONDITIONS_NOT_SAT >> 8);
                resp[rlen++] = (uint8_t)(SW_CONDITIONS_NOT_SAT);
                break;
            }

            /* check-only: no signature, just user-presence result. */
            if (control == U2F_AUTH_CHECK_ONLY) {
                resp[rlen++] = 0x01; /* user presence confirmed */
                resp[rlen++] = (uint8_t)(SW_NO_ERROR >> 8);
                resp[rlen++] = (uint8_t)(SW_NO_ERROR);
                break;
            }

            uint8_t sig[64];
            if (!auth_sign(app, challenge, slot->private_key, sig)) {
                send_error(cid, ERR_INVALID_PAR);
                return;
            }

            /* user presence(1) || counter(4) || signature(64) */
            resp[rlen++] = 0x01;
            be32(resp + rlen, u2f_counter);
            rlen += 4;
            memcpy(resp + rlen, sig, 64);
            rlen += 64;
            u2f_counter++;
            resp[rlen++] = (uint8_t)(SW_NO_ERROR >> 8);
            resp[rlen++] = (uint8_t)(SW_NO_ERROR);
            break;
        }

        case U2F_REGISTER: {
            /* Find a free slot for the new credential. */
            unsigned new_slot = FJ_NUM_SLOTS;
            for (unsigned i = 0; i < FJ_NUM_SLOTS; i++) {
                if (fj_keys_get(i) == NULL) { new_slot = i; break; }
            }
            if (new_slot >= FJ_NUM_SLOTS || fj_state_get() != FJ_STATE_UNLOCKED) {
                resp[rlen++] = (uint8_t)(SW_CONDITIONS_NOT_SAT >> 8);
                resp[rlen++] = (uint8_t)(SW_CONDITIONS_NOT_SAT);
                break;
            }

            /* Register payload: challenge(32) || app(32). */
            (void)data;

            char name[16];
            snprintf(name, sizeof(name), "cred%u", new_slot);
            if (!fj_keys_provision(new_slot, name, true)) {
                resp[rlen++] = (uint8_t)(SW_WRONG_DATA >> 8);
                resp[rlen++] = (uint8_t)(SW_WRONG_DATA);
                break;
            }

            const fj_slot_t *slot = fj_keys_get(new_slot);
            if (!slot) {
                resp[rlen++] = (uint8_t)(SW_WRONG_DATA >> 8);
                resp[rlen++] = (uint8_t)(SW_WRONG_DATA);
                break;
            }

            /* Derive the public key. */
            uint8_t pub[65];
            if (!derive_pubkey(slot->private_key, pub)) {
                resp[rlen++] = (uint8_t)(SW_WRONG_DATA >> 8);
                resp[rlen++] = (uint8_t)(SW_WRONG_DATA);
                break;
            }

            /* key handle = slot index (1 byte) + slot name. */
            uint8_t key_handle[FJ_SLOT_NAME_MAX + 1];
            key_handle[0] = (uint8_t)new_slot;
            memcpy(key_handle + 1, slot->name, strlen(slot->name));
            uint8_t kh_len = (uint8_t)(1 + strlen(slot->name));

            /* Build response (attestation removed: no X.509 cert / sig):
             * reserved(1) || pubkey(65) || kh_len(1) || key_handle */
            resp[rlen++] = 0x05;                        /* reserved */
            memcpy(resp + rlen, pub, 65); rlen += 65;
            resp[rlen++] = kh_len;
            memcpy(resp + rlen, key_handle, kh_len); rlen += kh_len;
            resp[rlen++] = (uint8_t)(SW_NO_ERROR >> 8);
            resp[rlen++] = (uint8_t)(SW_NO_ERROR);
            break;
        }

        default:
    }

    send_hid(cid, U2FHID_MSG, resp, rlen);
}

/* Handle a U2FHID MSG by routing to APDU handling. */
static void handle_msg(uint32_t cid, const uint8_t *payload, uint16_t len) {
    handle_apdu(cid, payload, len);
}

static void handle_init(uint32_t cid) {
    uint8_t resp[64];
    uint32_t new_cid = cid;

    /* Non-broadcast channel gets a fresh channel id. */
    if (cid != 0xffffffffu) {
        new_cid = (uint32_t)(u2f_counter ^ 0x5A5A5A5Au) | 0x80000000u;
        u2f_counter++;
    }

    memset(resp, 0, sizeof(resp));
    resp[0] = (uint8_t)(new_cid >> 24);
    resp[1] = (uint8_t)(new_cid >> 16);
    resp[2] = (uint8_t)(new_cid >> 8);
    resp[3] = (uint8_t)(new_cid);
    /* protocol version 2, version major/minor/build, cap flags */
    resp[4] = 2;
    resp[5] = 1;  /* major */
    resp[6] = 0;  /* minor */
    resp[7] = 0;  /* build */
    resp[8] = 0x04;  /* capabilities: CBOR (CTAP2) supported */
    /* nonce echoed */
    if (rx.len >= 8) memcpy(resp + 9, rx.buf, 8);

    /* Whole INIT response must be 17 bytes: 4 + 1 + 4 + 8 */
    send_hid(new_cid, U2FHID_INIT, resp, 17);
}

static void handle_ping(uint32_t cid, const uint8_t *payload, uint16_t len) {
    send_hid(cid, U2FHID_PING, payload, len);
}

/* Handle a CTAP2 CBOR message carried in a U2FHID CBOR (0x10) message. */
static void handle_cbor(uint32_t cid, const uint8_t *payload, uint16_t len) {
    uint8_t resp[512];
    size_t rlen = fj_ctap2_dispatch(payload, len, resp, sizeof(resp));
    if (rlen == 0) {
        send_error(cid, ERR_INVALID_PAR);
        return;
    }
    send_hid(cid, U2FHID_CBOR, resp, (uint16_t)rlen);
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
    /* Outbound reports are drained by the HID callback via pop_report. */
}