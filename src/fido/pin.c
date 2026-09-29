/*
 * Fjaeger - CTAP2 authenticatorClientPIN (0x06), PIN/UV auth protocol 1.
 */
#include <string.h>

#include "pin.h"
#include "cbor.h"
#include "crypto.h"
#include "keys.h"
#include "state.h"

/* authenticatorClientPIN request keys */
#define R_PROTOCOL       0x01
#define R_SUBCOMMAND     0x02
#define R_KEY_AGREEMENT  0x03
#define R_PIN_HASH_ENC   0x06

/* authenticatorClientPIN response keys */
#define RSP_KEY_AGREEMENT 0x01
#define RSP_PIN_TOKEN     0x02
#define RSP_PIN_RETRIES   0x03

/* subCommands */
#define SC_GET_PIN_RETRIES    0x01
#define SC_GET_KEY_AGREEMENT  0x02
#define SC_GET_PIN_TOKEN      0x05

/* COSE_Key header keys (crv/x/y are negative integers). */
#define COSE_KEY_KTY 0x01
#define COSE_KEY_ALG 0x03

/* CTAP2 error codes reused here. */
#define ERR_INVALID_PARAMETER 0x02
#define ERR_MISSING_PARAMETER 0x04
#define ERR_INVALID_COMMAND   0x01
#define ERR_PIN_INVALID       0x32
#define ERR_PIN_BLOCKED       0x34

/* Shared PIN/UV auth protocol 1 state. */
static uint8_t auth_priv[32];                 /* ephemeral key-agreement key */
static uint8_t pin_token[FJ_PIN_TOKEN_LEN];   /* the pinUvAuthToken */
static bool    token_valid = false;

void fj_pin_init(void) {
    if (!fj_ecdsa_generate_private(auth_priv))
        memset(auth_priv, 0, sizeof(auth_priv));
    fj_random(pin_token, sizeof(pin_token));
    token_valid = true;
}

void fj_pin_reset_token(void) {
    token_valid = false;
}

static size_t ctap_err(uint8_t *out, size_t cap, uint8_t code) {
    if (cap < 1) return 0;
    out[0] = code;
    return 1;
}

/* Encode the authenticator's ephemeral public key as a COSE_Key with
 * alg = -25 (ECDH), as required by getPublicKey in PIN/UV auth protocol 1. */
static void encode_cose_ecdh(uint8_t *out, size_t cap, const uint8_t pub[65],
                             size_t *len) {
    fj_cbor_writer w;
    fj_cbor_writer_init(&w, out, cap);
    fj_cbor_map(&w, 5);
    fj_cbor_uint(&w, 1);  fj_cbor_uint(&w, 2);      /* kty: EC2 */
    fj_cbor_uint(&w, 3);  fj_cbor_neg(&w, 24);      /* alg: -25 */
    fj_cbor_neg(&w, 0);   fj_cbor_uint(&w, 1);      /* crv: P-256 */
    fj_cbor_neg(&w, 1);   fj_cbor_bstr(&w, pub + 1, 32); /* x */
    fj_cbor_neg(&w, 2);   fj_cbor_bstr(&w, pub + 33, 32); /* y */
    if (!fj_cbor_ok(&w)) { *len = 0; return; }
    *len = w.len;
}

/* sharedSecret = SHA-256(ECDH(auth_priv, platform_pub)) per PIN protocol 1. */
static bool compute_shared_secret(const uint8_t platform_pub[65],
                                  uint8_t secret[32]) {
    uint8_t z[32];
    if (!fj_ecdh_shared_secret(auth_priv, platform_pub, z)) {
        fj_secure_zero(z, sizeof(z));
        return false;
    }
    fj_sha256(z, sizeof(z), secret);
    fj_secure_zero(z, sizeof(z));
    return true;
}

/* Parse a COSE_Key map (the platform key-agreement key) and extract the
 * uncompressed P-256 point into pub[65]. */
static bool parse_platform_key(fj_cbor_reader *r, fj_cbor_item *item,
                               uint8_t pub[65]) {
    if (item->type != FJ_CBOR_MAP) return false;
    size_t pairs = (size_t)item->val;
    uint8_t x[32], y[32];
    bool have_x = false, have_y = false, crv_ok = false;
    for (size_t i = 0; i < pairs; i++) {
        fj_cbor_item k, v;
        if (!fj_cbor_next(r, &k)) return false;
        if (!fj_cbor_next(r, &v)) return false;
        if (k.type == FJ_CBOR_UINT) {
            if (k.val == 0x20) { /* crv: -1 would be a neg, but accept uint 0x20 defensively */
                if (v.type == FJ_CBOR_UINT && v.val == 1) crv_ok = true;
                else if (!fj_cbor_skip(r, &v)) return false;
            } else if (!fj_cbor_skip(r, &v)) {
                return false;
            }
        } else if (k.type == FJ_CBOR_NEG) {
            if (k.val == 1) {           /* key -2 = x */
                size_t n = 0;
                if (v.type != FJ_CBOR_BSTR ||
                    !fj_cbor_read_bytes(r, &v, x, sizeof(x), &n) || n != 32)
                    return false;
                have_x = true;
            } else if (k.val == 2) {    /* key -3 = y */
                size_t n = 0;
                if (v.type != FJ_CBOR_BSTR ||
                    !fj_cbor_read_bytes(r, &v, y, sizeof(y), &n) || n != 32)
                    return false;
                have_y = true;
            } else if (k.val == 0) {    /* key -1 = crv */
                if (v.type == FJ_CBOR_UINT && v.val == 1) crv_ok = true;
                else if (!fj_cbor_skip(r, &v)) return false;
            } else {
                if (!fj_cbor_skip(r, &v)) return false;
            }
        } else {
            if (!fj_cbor_skip(r, &v)) return false;
        }
    }
    if (!have_x || !have_y || !crv_ok) return false;
    pub[0] = 0x04;
    memcpy(pub + 1, x, 32);
    memcpy(pub + 33, y, 32);
    return true;
}

static unsigned pin_retries(void) {
    fj_security_t sec;
    if (!fj_keys_get_security(&sec)) return 0;
    if (sec.ctap_pin_blocked) return 0;
    unsigned used = sec.ctap_pin_fail;
    if (used >= FJ_MAX_PIN_FAILS) return 0;
    return FJ_MAX_PIN_FAILS - used;
}

/* Handle the getPinToken (0x05) subcommand. */
static size_t get_pin_token(const uint8_t *req, size_t len,
                            uint8_t *out, size_t cap) {
    fj_cbor_reader r;
    fj_cbor_reader_init(&r, req, len);

    fj_cbor_item root;
    if (!fj_cbor_next(&r, &root) || root.type != FJ_CBOR_MAP)
        return ctap_err(out, cap, ERR_INVALID_PARAMETER);

    size_t pairs = (size_t)root.val;
    uint8_t platform_pub[65];
    bool have_key = false;
    uint8_t pin_hash_enc[16];
    bool have_hash = false;
    bool proto_ok = false;

    for (size_t i = 0; i < pairs; i++) {
        fj_cbor_item k, v;
        if (!fj_cbor_next(&r, &k) || k.type != FJ_CBOR_UINT) return ctap_err(out, cap, ERR_INVALID_PARAMETER);
        if (!fj_cbor_next(&r, &v)) return ctap_err(out, cap, ERR_INVALID_PARAMETER);
        switch (k.val) {
            case R_PROTOCOL:
                if (v.type == FJ_CBOR_UINT && v.val == FJ_PIN_PROTOCOL)
                    proto_ok = true;
                else if (!fj_cbor_skip(&r, &v)) return ctap_err(out, cap, ERR_INVALID_PARAMETER);
                break;
            case R_KEY_AGREEMENT:
                if (!parse_platform_key(&r, &v, platform_pub))
                    return ctap_err(out, cap, ERR_INVALID_PARAMETER);
                have_key = true;
                break;
            case R_PIN_HASH_ENC: {
                size_t n = 0;
                if (v.type != FJ_CBOR_BSTR ||
                    !fj_cbor_read_bytes(&r, &v, pin_hash_enc, sizeof(pin_hash_enc), &n) ||
                    n != sizeof(pin_hash_enc))
                    return ctap_err(out, cap, ERR_INVALID_PARAMETER);
                have_hash = true;
                break;
            }
            default:
                if (!fj_cbor_skip(&r, &v)) return ctap_err(out, cap, ERR_INVALID_PARAMETER);
                break;
        }
    }

    if (!proto_ok || !have_key || !have_hash)
        return ctap_err(out, cap, ERR_MISSING_PARAMETER);

    /* Brute-force protection. */
    fj_security_t sec;
    if (!fj_keys_get_security(&sec)) return ctap_err(out, cap, ERR_INVALID_PARAMETER);
    if (sec.ctap_pin_blocked) return ctap_err(out, cap, ERR_PIN_BLOCKED);
    if (!fj_state_brute_ok(FJ_BRUTE_CTAP)) return ctap_err(out, cap, ERR_PIN_BLOCKED);

    uint8_t secret[32];
    if (!compute_shared_secret(platform_pub, secret))
        return ctap_err(out, cap, ERR_INVALID_PARAMETER);

    /* Decrypt LEFT(SHA-256(PIN),16). */
    uint8_t left16[16];
    uint8_t zero_iv[16] = {0};
    memcpy(left16, pin_hash_enc, 16);
    if (!fj_aes_cbc(secret, zero_iv, left16, sizeof(left16), false))
        return ctap_err(out, cap, ERR_INVALID_PARAMETER);

    /* Verify against the CTAP2 client-PIN verifier (LEFT(SHA-256(pin),16)).
     * The CTAP2 PIN is independent of the device unlock passphrase, so a
     * fast brute-force of this verifier yields at most a pinUvAuthToken and
     * never the master key M. */
    if (!fj_state_ctap2_verify(left16)) {
        sec.ctap_pin_fail++;
        if (sec.ctap_pin_fail >= FJ_MAX_PIN_FAILS) sec.ctap_pin_blocked = 1;
        fj_keys_set_security(&sec);
        fj_state_brute_failure(FJ_BRUTE_CTAP);
        return ctap_err(out, cap, sec.ctap_pin_blocked ? ERR_PIN_BLOCKED
                                                       : ERR_PIN_INVALID);
    }

    /* Correct (or dummy-mode): reset the retry counter and mint a token. */
    if (sec.ctap_pin_fail != 0 || sec.ctap_pin_blocked) {
        sec.ctap_pin_fail = 0;
        sec.ctap_pin_blocked = 0;
        fj_keys_set_security(&sec);
    }
    fj_state_brute_success(FJ_BRUTE_CTAP);
    fj_random(pin_token, sizeof(pin_token));
    token_valid = true;

    /* Return the token encrypted with the shared secret. */
    uint8_t tok_enc[FJ_PIN_TOKEN_LEN];
    memcpy(tok_enc, pin_token, FJ_PIN_TOKEN_LEN);
    if (!fj_aes_cbc(secret, zero_iv, tok_enc, sizeof(tok_enc), true))
        return ctap_err(out, cap, ERR_INVALID_PARAMETER);

    if (cap < 2) return 0;
    out[0] = 0;
    fj_cbor_writer w;
    fj_cbor_writer_init(&w, out + 1, cap - 1);
    fj_cbor_map(&w, 1);
    fj_cbor_uint(&w, RSP_PIN_TOKEN);
    fj_cbor_bstr(&w, tok_enc, sizeof(tok_enc));
    if (!fj_cbor_ok(&w)) return 0;
    return w.len + 1;
}

size_t fj_ctap2_client_pin(const uint8_t *req, size_t len,
                           uint8_t *out, size_t cap) {
    fj_cbor_reader r;
    fj_cbor_reader_init(&r, req, len);

    fj_cbor_item root;
    if (!fj_cbor_next(&r, &root) || root.type != FJ_CBOR_MAP)
        return ctap_err(out, cap, ERR_INVALID_PARAMETER);

    size_t pairs = (size_t)root.val;
    unsigned subcmd = 0xff;
    bool have_subcmd = false;
    bool proto_ok = false;

    /* The request map only needs the subcommand and (for getKeyAgreement)
     * the protocol. Scan for those, skip the rest. */
    for (size_t i = 0; i < pairs; i++) {
        fj_cbor_item k, v;
        if (!fj_cbor_next(&r, &k) || k.type != FJ_CBOR_UINT)
            return ctap_err(out, cap, ERR_INVALID_PARAMETER);
        if (!fj_cbor_next(&r, &v))
            return ctap_err(out, cap, ERR_INVALID_PARAMETER);
        if (k.val == R_SUBCOMMAND && v.type == FJ_CBOR_UINT) {
            subcmd = (unsigned)v.val;
            have_subcmd = true;
        } else if (k.val == R_PROTOCOL && v.type == FJ_CBOR_UINT &&
                   v.val == FJ_PIN_PROTOCOL) {
            proto_ok = true;
        }
        if (!fj_cbor_skip(&r, &v))
            return ctap_err(out, cap, ERR_INVALID_PARAMETER);
    }

    if (!have_subcmd)
        return ctap_err(out, cap, ERR_MISSING_PARAMETER);

    switch (subcmd) {
        case SC_GET_KEY_AGREEMENT: {
            /* getKeyAgreement requires pinUvAuthProtocol to be present. */
            if (!proto_ok) return ctap_err(out, cap, ERR_MISSING_PARAMETER);
            /* Regenerate the ephemeral key so each transaction is fresh. */
            if (!fj_ecdsa_generate_private(auth_priv))
                return ctap_err(out, cap, ERR_INVALID_PARAMETER);
            uint8_t pub[65];
            if (!fj_ecdsa_pubkey(auth_priv, pub))
                return ctap_err(out, cap, ERR_INVALID_PARAMETER);
            uint8_t cose[128];
            size_t clen = 0;
            encode_cose_ecdh(cose, sizeof(cose), pub, &clen);
            if (clen == 0 || cap < 2) return 0;
            out[0] = 0;
            fj_cbor_writer w;
            fj_cbor_writer_init(&w, out + 1, cap - 1);
            fj_cbor_map(&w, 1);
            fj_cbor_uint(&w, RSP_KEY_AGREEMENT);
            /* Copy the pre-encoded COSE key bytes into the writer. */
            if (clen > cap - 1 - w.len) return 0;
            memcpy(w.buf + w.len, cose, clen);
            w.len += clen;
            if (!fj_cbor_ok(&w)) return 0;
            return w.len + 1;
        }
        case SC_GET_PIN_RETRIES: {
            if (cap < 2) return 0;
            out[0] = 0;
            fj_cbor_writer w;
            fj_cbor_writer_init(&w, out + 1, cap - 1);
            fj_cbor_map(&w, 1);
            fj_cbor_uint(&w, RSP_PIN_RETRIES);
            fj_cbor_uint(&w, pin_retries());
            if (!fj_cbor_ok(&w)) return 0;
            return w.len + 1;
        }
        case SC_GET_PIN_TOKEN:
            return get_pin_token(req, len, out, cap);
        default:
            return ctap_err(out, cap, ERR_INVALID_COMMAND);
    }
}

bool fj_pin_verify_auth(const uint8_t *message, size_t message_len,
                        const uint8_t param[16]) {
    if (!token_valid) return false;
    uint8_t mac[32];
    if (!fj_hmac_sha256(pin_token, FJ_PIN_TOKEN_LEN, message, message_len, mac)) return false;
    bool ok = fj_ct_equal(mac, param, 16);
    memset(mac, 0, sizeof(mac));
    return ok;
}
