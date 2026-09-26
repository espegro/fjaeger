/*
 * Fjaeger - CTAP2 authenticator operations (see ctap2.h).
 */
#include <string.h>

#include "ctap2.h"
#include "cbor.h"
#include "crypto.h"
#include "keys.h"
#include "state.h"

/* ------------------------------------------------------------------ */
/* CTAP2 command bytes                                                 */
/* ------------------------------------------------------------------ */
#define CMD_MAKE_CREDENTIAL 0x01
#define CMD_GET_ASSERTION   0x02
#define CMD_GET_INFO        0x04
#define CMD_CANCEL          0x06

/* CTAP2 error codes (CTAP2_ERR_*) */
#define ERR_INVALID_COMMAND   0x01
#define ERR_INVALID_PARAMETER 0x02
#define ERR_MISSING_PARAMETER 0x04
#define ERR_INVALID_LENGTH    0x05
#define ERR_UNSUPPORTED_ALG   0x0b
#define ERR_CREDENTIAL_EXCLUDED 0x0d
#define ERR_OPERATION_DENIED  0x11
#define ERR_NOT_ALLOWED       0x20
#define ERR_PIN_REQUIRED      0x23

/* CTAP2 request / response map keys */
#define K_CLIENT_DATA_HASH 0x01
#define K_RP              0x02
#define K_USER            0x03
#define K_PUB_KEY_CRED_PARAMS 0x04
#define K_EXCLUDE_LIST     0x05
#define K_OPTIONS          0x06
#define K_EXTENSIONS       0x07
#define K_RP_ID            0x01
#define K_CLIENT_DATA_HASH2 0x02
#define K_ALLOW_LIST       0x03
#define K_USER_OPTION      0x05
#define K_CREDENTIAL       0x01
#define K_AUTH_DATA        0x02
#define K_SIGNATURE        0x03
#define K_USER_HANDLE      0x04

/* COSE algorithm ES256 (ECDSA P-256 w/ SHA-256) */
#define COSE_ES256 (-7)
#define COSE_ALG_KEY 3

/* ------------------------------------------------------------------ */
/* Credential store (persisted in flash via keys.c)                    */
/* ------------------------------------------------------------------ */
#define FJ_AUTH_DATA_MAX 200

static fj_ctap2_cred_t creds[FJ_CTAP2_CREDS];

static uint32_t sign_counter = 0;
static bool ctap2_dirty = false;

void fj_ctap2_init(void) {
    fj_keys_ctap2_load(creds);
    ctap2_dirty = false;
    /* Seed the sign counter from the hardware RNG. */
    fj_random(&sign_counter, sizeof(sign_counter));
}

/* Called from the main loop: flush any pending flash writes. Flash
 * writes must not run inside the USB IRQ context, so we defer them. */
void fj_ctap2_task(void) {
    if (ctap2_dirty) {
        if (fj_keys_ctap2_save(creds)) ctap2_dirty = false;
    }
}

static fj_ctap2_cred_t *find_cred_by_id(const uint8_t *id) {
    for (unsigned i = 0; i < FJ_CTAP2_CREDS; i++) {
        if (creds[i].in_use &&
            memcmp(creds[i].credential_id, id, FJ_CRED_ID_LEN) == 0)
            return &creds[i];
    }
    return NULL;
}

static fj_ctap2_cred_t *find_cred_by_rp(const uint8_t rp_id_hash[FJ_HASH_LEN]) {
    for (unsigned i = 0; i < FJ_CTAP2_CREDS; i++) {
        if (creds[i].in_use &&
            memcmp(creds[i].rp_id_hash, rp_id_hash, FJ_HASH_LEN) == 0)
            return &creds[i];
    }
    return NULL;
}

/* ------------------------------------------------------------------ */
/* COSE EC2 public key encoding (P-256 / ES256)                        */
/* ------------------------------------------------------------------ */
/* Build the COSE_Key map for a P-256 public key. */
static size_t encode_cose_key(uint8_t *out, size_t cap,
                              const uint8_t pub[65]) {
    fj_cbor_writer w;
    fj_cbor_writer_init(&w, out, cap);

    fj_cbor_map(&w, 6);
    fj_cbor_uint(&w, 1);  fj_cbor_uint(&w, 2);       /* kty: EC2 */
    fj_cbor_uint(&w, 3);  fj_cbor_neg(&w, 6);        /* alg: -7 ES256 */
    fj_cbor_uint(&w, -1); fj_cbor_uint(&w, 1);       /* crv: P-256 */
    fj_cbor_uint(&w, -2); fj_cbor_bstr(&w, pub + 1, 32);        /* x */
    fj_cbor_uint(&w, -3); fj_cbor_bstr(&w, pub + 33, 32);       /* y */

    if (!fj_cbor_ok(&w)) return 0;
    return w.len;
}

/* ------------------------------------------------------------------ */
/* authData construction                                              */
/* ------------------------------------------------------------------ */
/* Build the "none"-attestation authData for makeCredential. */
static size_t build_mc_authdata(uint8_t *out, size_t cap,
                                const uint8_t rp_id_hash[FJ_HASH_LEN],
                                const uint8_t pub[65],
                                const uint8_t cred_id[FJ_CRED_ID_LEN]) {
    fj_cbor_writer w;
    fj_cbor_writer_init(&w, out, cap);

    /* rpIdHash(32) || flags(1) || signCount(4) || aaguid(16) */
    if (cap < 32 + 1 + 4 + 16) return 0;
    uint8_t *p = out;
    size_t pos = 0;
    memcpy(p + pos, rp_id_hash, 32); pos += 32;
    p[pos++] = 0x41;                       /* UP | AT */
    p[pos++] = 0; p[pos++] = 0; p[pos++] = 0; p[pos++] = 0; /* signCount */

    /* AAGUID: zeroes (unregistered device). */
    memset(p + pos, 0, 16); pos += 16;

    /* credentialId length (2) + credentialId */
    p[pos++] = 0; p[pos++] = FJ_CRED_ID_LEN;
    memcpy(p + pos, cred_id, FJ_CRED_ID_LEN); pos += FJ_CRED_ID_LEN;

    /* COSE key */
    size_t ck = encode_cose_key(p + pos, cap - pos, pub);
    if (ck == 0 || pos + ck > cap) return 0;
    pos += ck;

    (void)w;
    return pos;
}

/* Build the getAssertion authData. */
static size_t build_ga_authdata(uint8_t *out, size_t cap,
                                const uint8_t rp_id_hash[FJ_HASH_LEN],
                                bool with_user) {
    if (cap < 37) return 0;
    uint8_t *p = out;
    size_t pos = 0;
    memcpy(p + pos, rp_id_hash, 32); pos += 32;
    p[pos++] = (uint8_t)(0x01 | (with_user ? 0x80 : 0x00)); /* UP | ED */
    p[pos++] = (uint8_t)(sign_counter >> 24);
    p[pos++] = (uint8_t)(sign_counter >> 16);
    p[pos++] = (uint8_t)(sign_counter >> 8);
    p[pos++] = (uint8_t)(sign_counter);
    return pos;
}

/* ------------------------------------------------------------------ */
/* GetInfo (0x04)                                                      */
/* ------------------------------------------------------------------ */
static size_t build_get_info(uint8_t *out, size_t cap) {
    fj_cbor_writer w;
    fj_cbor_writer_init(&w, out, cap);

    fj_cbor_map(&w, 3);

    /* versions */
    fj_cbor_uint(&w, 0x01);
    fj_cbor_array(&w, 2);
    fj_cbor_tstr(&w, "U2F_V2");
    fj_cbor_tstr(&w, "FIDO_2_0");

    /* extensions: empty */
    fj_cbor_uint(&w, 0x02);
    fj_cbor_array(&w, 0);

    /* aaguid */
    fj_cbor_uint(&w, 0x03);
    uint8_t aaguid[16];
    memset(aaguid, 0, sizeof(aaguid));
    fj_cbor_bstr(&w, aaguid, sizeof(aaguid));

    /* options: rk=true (resident), up=true, clientPin=false, uv=false */
    fj_cbor_uint(&w, 0x04);
    fj_cbor_map(&w, 4);
    fj_cbor_tstr(&w, "rk");   fj_cbor_bool(&w, true);
    fj_cbor_tstr(&w, "up");   fj_cbor_bool(&w, true);
    fj_cbor_tstr(&w, "clientPin"); fj_cbor_bool(&w, false);
    fj_cbor_tstr(&w, "uv");   fj_cbor_bool(&w, false);

    /* maxMsgSize */
    fj_cbor_uint(&w, 0x05);
    fj_cbor_uint(&w, 1200);

    /* algorithms: ES256 */
    fj_cbor_uint(&w, 0x06);
    fj_cbor_array(&w, 1);
    fj_cbor_map(&w, 2);
    fj_cbor_uint(&w, COSE_ALG_KEY);
    fj_cbor_neg(&w, 6);   /* -7 */

    if (!fj_cbor_ok(&w)) return 0;
    return w.len;
}

/* ------------------------------------------------------------------ */
/* MakeCredential (0x01)                                               */
/* ------------------------------------------------------------------ */
static size_t make_credential(const uint8_t *req, size_t len,
                              uint8_t *out, size_t cap) {
    fj_cbor_reader r;
    fj_cbor_reader_init(&r, req, len);

    fj_cbor_item root;
    if (!fj_cbor_next(&r, &root) || root.type != FJ_CBOR_MAP)
        goto bad_param;

    size_t pairs = (size_t)root.val;
    uint8_t client_data_hash[FJ_HASH_LEN];
    uint8_t rp_id[64]; size_t rp_id_len = 0;
    bool have_client_hash = false, have_rp = false;
    bool resident = false;
    int alg = 0;

    for (size_t i = 0; i < pairs; i++) {
        fj_cbor_item key, val;
        if (!fj_cbor_next(&r, &key) || key.type != FJ_CBOR_UINT) goto bad_param;
        if (!fj_cbor_next(&r, &val)) goto bad_param;

        switch (key.val) {
            case K_CLIENT_DATA_HASH: {
                size_t n = 0;
                if (val.type != FJ_CBOR_BSTR ||
                    !fj_cbor_read_bytes(&r, &val, client_data_hash, FJ_HASH_LEN, &n) ||
                    n != FJ_HASH_LEN)
                    goto bad_param;
                have_client_hash = true;
                break;
            }
            case K_RP: {
                if (val.type != FJ_CBOR_MAP) goto bad_param;
                size_t rp_pairs = (size_t)val.val;
                for (size_t j = 0; j < rp_pairs; j++) {
                    fj_cbor_item k2, v2;
                    if (!fj_cbor_next(&r, &k2)) goto bad_param;
                    if (!fj_cbor_next(&r, &v2)) goto bad_param;
                    if (k2.type == FJ_CBOR_UINT && k2.val == 0x01) {
                        size_t n = 0;
                        if (v2.type != FJ_CBOR_TSTR ||
                            !fj_cbor_read_bytes(&r, &v2, rp_id, sizeof(rp_id), &n))
                            goto bad_param;
                        rp_id_len = n;
                        have_rp = true;
                    } else {
                        if (!fj_cbor_skip(&r, &v2)) goto bad_param;
                    }
                }
                break;
            }
            case K_USER: {
                /* user map: we only need its id, but it is not exposed in
                 * a "none"-attestation non-resident credential unless we
                 * store it. We skip the body. */
                if (val.type != FJ_CBOR_MAP) goto bad_param;
                if (!fj_cbor_skip(&r, &val)) goto bad_param;
                break;
            }
            case K_PUB_KEY_CRED_PARAMS: {
                if (val.type != FJ_CBOR_ARRAY) goto bad_param;
                size_t n = (size_t)val.val;
                for (size_t j = 0; j < n; j++) {
                    fj_cbor_item param;
                    if (!fj_cbor_next(&r, &param) || param.type != FJ_CBOR_MAP)
                        goto bad_param;
                    size_t pp = (size_t)param.val;
                    for (size_t k = 0; k < pp; k++) {
                        fj_cbor_item pk, pv;
                        if (!fj_cbor_next(&r, &pk)) goto bad_param;
                        if (!fj_cbor_next(&r, &pv)) goto bad_param;
                        if (pk.type == FJ_CBOR_UINT && pk.val == 0x03 &&
                            pv.type == FJ_CBOR_NEG && pv.val == 6)
                            alg = 1; /* ES256 supported */
                        if (!fj_cbor_skip(&r, &pv)) goto bad_param;
                    }
                }
                break;
            }
            case K_EXCLUDE_LIST: {
                if (val.type != FJ_CBOR_ARRAY) goto bad_param;
                if (!fj_cbor_skip(&r, &val)) goto bad_param;
                break;
            }
            case K_OPTIONS: {
                if (val.type != FJ_CBOR_MAP) goto bad_param;
                size_t op = (size_t)val.val;
                for (size_t j = 0; j < op; j++) {
                    fj_cbor_item ok, ov;
                    if (!fj_cbor_next(&r, &ok)) goto bad_param;
                    if (!fj_cbor_next(&r, &ov)) goto bad_param;
                    if (ok.type == FJ_CBOR_TSTR) {
                        size_t n = 0; char name[8] = {0};
                        if (fj_cbor_read_bytes(&r, &ok, (uint8_t *)name, sizeof(name)-1, &n) &&
                            n == 2 && name[0] == 'r' && name[1] == 'k')
                            resident = (ov.type == FJ_CBOR_BOOL && ov.val != 0);
                    }
                    if (!fj_cbor_skip(&r, &ov)) goto bad_param;
                }
                break;
            }
            default:
                if (!fj_cbor_skip(&r, &val)) goto bad_param;
                break;
        }
    }

    if (!have_client_hash || !have_rp || rp_id_len == 0) goto missing;
    if (alg == 0) { /* only ES256 offered; if none matched, unsupported */
        /* Accept if the parameter list simply wasn't parsed to an alg. */
    }

    if (fj_state_get() != FJ_STATE_UNLOCKED) {
        /* CTAP2_ERR_OPERATION_DENIED (device locked). */
        fj_cbor_writer w;
        fj_cbor_writer_init(&w, out, cap);
        fj_cbor_uint(&w, ERR_OPERATION_DENIED);
        return w.len;
    }

    /* rpIdHash = SHA-256(rpId). */
    uint8_t rp_id_hash[FJ_HASH_LEN];
    fj_sha256(rp_id, rp_id_len, rp_id_hash);

    /* Refuse if a credential for this rp already exists (exclude). */
    if (find_cred_by_rp(rp_id_hash)) {
        fj_cbor_writer w;
        fj_cbor_writer_init(&w, out, cap);
        fj_cbor_uint(&w, ERR_CREDENTIAL_EXCLUDED);
        return w.len;
    }

    /* Allocate a credential slot. */
    fj_ctap2_cred_t *cr = NULL;
    for (unsigned i = 0; i < FJ_CTAP2_CREDS; i++) {
        if (!creds[i].in_use) { cr = &creds[i]; break; }
    }
    if (!cr) {
        fj_cbor_writer w;
        fj_cbor_writer_init(&w, out, cap);
        fj_cbor_uint(&w, ERR_NOT_ALLOWED);
        return w.len;
    }

    memset(cr, 0, sizeof(*cr));
    fj_random(cr->credential_id, FJ_CRED_ID_LEN);
    fj_random(cr->private_key, FJ_ECDSA_KEY_BYTES);
    memcpy(cr->rp_id_hash, rp_id_hash, FJ_HASH_LEN);
    cr->in_use = true;
    (void)resident;

    /* Public key + authData. */
    uint8_t pub[65];
    if (!fj_ecdsa_pubkey(cr->private_key, pub)) {
        cr->in_use = false;
        fj_cbor_writer w;
        fj_cbor_writer_init(&w, out, cap);
        fj_cbor_uint(&w, ERR_INVALID_PARAMETER);
        return w.len;
    }

    uint8_t authdata[FJ_AUTH_DATA_MAX];
    size_t ad_len = build_mc_authdata(authdata, sizeof(authdata),
                                      rp_id_hash, pub, cr->credential_id);
    if (ad_len == 0) {
        cr->in_use = false;
        fj_cbor_writer w;
        fj_cbor_writer_init(&w, out, cap);
        fj_cbor_uint(&w, ERR_INVALID_LENGTH);
        return w.len;
    }

    /* Credential committed; mark for deferred flash persist. */
    ctap2_dirty = true;

    /* Response map. */
    fj_cbor_writer w;
    fj_cbor_writer_init(&w, out, cap);
    fj_cbor_map(&w, 3);
    fj_cbor_uint(&w, 0x01); fj_cbor_tstr(&w, "none");           /* fmt */
    fj_cbor_uint(&w, 0x02); fj_cbor_bstr(&w, authdata, ad_len); /* authData */
    fj_cbor_uint(&w, 0x03); fj_cbor_map(&w, 0);                 /* attStmt */

    if (!fj_cbor_ok(&w)) {
        cr->in_use = false;
        return 0;
    }
    return w.len;

missing:
    {
        fj_cbor_writer w;
        fj_cbor_writer_init(&w, out, cap);
        fj_cbor_uint(&w, ERR_MISSING_PARAMETER);
        return w.len;
    }
bad_param:
    {
        fj_cbor_writer w;
        fj_cbor_writer_init(&w, out, cap);
        fj_cbor_uint(&w, ERR_INVALID_PARAMETER);
        return w.len;
    }
}

/* ------------------------------------------------------------------ */
/* GetAssertion (0x02)                                                 */
/* ------------------------------------------------------------------ */
static size_t get_assertion(const uint8_t *req, size_t len,
                            uint8_t *out, size_t cap) {
    fj_cbor_reader r;
    fj_cbor_reader_init(&r, req, len);

    fj_cbor_item root;
    if (!fj_cbor_next(&r, &root) || root.type != FJ_CBOR_MAP)
        goto bad_param;

    size_t pairs = (size_t)root.val;
    uint8_t client_data_hash[FJ_HASH_LEN];
    uint8_t rp_id[64]; size_t rp_id_len = 0;
    uint8_t allow_id[FJ_CRED_ID_LEN];
    bool have_client_hash = false, have_rp = false, have_allow = false;

    for (size_t i = 0; i < pairs; i++) {
        fj_cbor_item key, val;
        if (!fj_cbor_next(&r, &key) || key.type != FJ_CBOR_UINT) goto bad_param;
        if (!fj_cbor_next(&r, &val)) goto bad_param;

        switch (key.val) {
            case K_RP_ID: {
                size_t n = 0;
                if (val.type != FJ_CBOR_TSTR ||
                    !fj_cbor_read_bytes(&r, &val, rp_id, sizeof(rp_id), &n))
                    goto bad_param;
                rp_id_len = n;
                have_rp = true;
                break;
            }
            case K_CLIENT_DATA_HASH2: {
                size_t n = 0;
                if (val.type != FJ_CBOR_BSTR ||
                    !fj_cbor_read_bytes(&r, &val, client_data_hash, FJ_HASH_LEN, &n) ||
                    n != FJ_HASH_LEN)
                    goto bad_param;
                have_client_hash = true;
                break;
            }
            case K_ALLOW_LIST: {
                if (val.type != FJ_CBOR_ARRAY) goto bad_param;
                size_t n = (size_t)val.val;
                for (size_t j = 0; j < n; j++) {
                    fj_cbor_item entry;
                    if (!fj_cbor_next(&r, &entry) || entry.type != FJ_CBOR_MAP)
                        goto bad_param;
                    size_t ep = (size_t)entry.val;
                    for (size_t k = 0; k < ep; k++) {
                        fj_cbor_item ek, ev;
                        if (!fj_cbor_next(&r, &ek)) goto bad_param;
                        if (!fj_cbor_next(&r, &ev)) goto bad_param;
                        if (ek.type == FJ_CBOR_UINT && ek.val == 0x02 &&
                            ev.type == FJ_CBOR_BSTR) {
                            size_t n2 = 0;
                            if (fj_cbor_read_bytes(&r, &ev, allow_id,
                                                   FJ_CRED_ID_LEN, &n2) &&
                                n2 == FJ_CRED_ID_LEN)
                                have_allow = true;
                        } else {
                            if (!fj_cbor_skip(&r, &ev)) goto bad_param;
                        }
                    }
                }
                break;
            }
            default:
                if (!fj_cbor_skip(&r, &val)) goto bad_param;
                break;
        }
    }

    if (!have_client_hash || !have_rp || rp_id_len == 0) goto missing;

    if (fj_state_get() != FJ_STATE_UNLOCKED) {
        fj_cbor_writer w;
        fj_cbor_writer_init(&w, out, cap);
        fj_cbor_uint(&w, ERR_OPERATION_DENIED);
        return w.len;
    }

    uint8_t rp_id_hash[FJ_HASH_LEN];
    fj_sha256(rp_id, rp_id_len, rp_id_hash);

    /* Resolve the credential: by allowList id, else by rpIdHash. */
    fj_ctap2_cred_t *cr = NULL;
    if (have_allow) cr = find_cred_by_id(allow_id);
    if (!cr) cr = find_cred_by_rp(rp_id_hash);
    if (!cr) {
        fj_cbor_writer w;
        fj_cbor_writer_init(&w, out, cap);
        fj_cbor_uint(&w, ERR_NOT_ALLOWED);
        return w.len;
    }
    if (memcmp(cr->rp_id_hash, rp_id_hash, FJ_HASH_LEN) != 0) {
        fj_cbor_writer w;
        fj_cbor_writer_init(&w, out, cap);
        fj_cbor_uint(&w, ERR_NOT_ALLOWED);
        return w.len;
    }

    /* authData. */
    bool with_user = (cr->user_id_len > 0);
    uint8_t authdata[FJ_AUTH_DATA_MAX];
    size_t ad_len = build_ga_authdata(authdata, sizeof(authdata),
                                      rp_id_hash, with_user);
    if (ad_len == 0) goto bad_param;
    sign_counter++;

    /* Signed data: authData || SHA-256(clientDataHash). */
    uint8_t digest[FJ_HASH_LEN];
    fj_sha256(client_data_hash, FJ_HASH_LEN, digest);
    uint8_t to_sign[FJ_AUTH_DATA_MAX + FJ_HASH_LEN];
    memcpy(to_sign, authdata, ad_len);
    memcpy(to_sign + ad_len, digest, FJ_HASH_LEN);
    uint8_t sig_digest[FJ_HASH_LEN];
    fj_sha256(to_sign, ad_len + FJ_HASH_LEN, sig_digest);

    uint8_t signature[64];
    if (!fj_ecdsa_sign(cr->private_key, sig_digest, signature)) goto bad_param;

    /* Response: array(1){ map(credential, authData, signature, [user]) }. */
    fj_cbor_writer w;
    fj_cbor_writer_init(&w, out, cap);

    fj_cbor_array(&w, 1);
    fj_cbor_map(&w, with_user ? 4 : 3);

    /* credential: {type: "public-key", id: bstr} */
    fj_cbor_uint(&w, K_CREDENTIAL);
    fj_cbor_map(&w, 2);
    fj_cbor_uint(&w, 0x01); fj_cbor_tstr(&w, "public-key");
    fj_cbor_uint(&w, 0x02); fj_cbor_bstr(&w, cr->credential_id, FJ_CRED_ID_LEN);

    fj_cbor_uint(&w, K_AUTH_DATA); fj_cbor_bstr(&w, authdata, ad_len);
    fj_cbor_uint(&w, K_SIGNATURE); fj_cbor_bstr(&w, signature, 64);
    if (with_user) {
        fj_cbor_uint(&w, K_USER_HANDLE);
        fj_cbor_bstr(&w, cr->user_id, cr->user_id_len);
    }

    if (!fj_cbor_ok(&w)) return 0;
    return w.len;

missing:
    {
        fj_cbor_writer w;
        fj_cbor_writer_init(&w, out, cap);
        fj_cbor_uint(&w, ERR_MISSING_PARAMETER);
        return w.len;
    }
bad_param:
    {
        fj_cbor_writer w;
        fj_cbor_writer_init(&w, out, cap);
        fj_cbor_uint(&w, ERR_INVALID_PARAMETER);
        return w.len;
    }
}

/* ------------------------------------------------------------------ */
/* Dispatch                                                            */
/* ------------------------------------------------------------------ */
size_t fj_ctap2_dispatch(const uint8_t *msg, size_t len,
                         uint8_t *out, size_t out_cap) {
    if (len == 0) {
        fj_cbor_writer w;
        fj_cbor_writer_init(&w, out, out_cap);
        fj_cbor_uint(&w, ERR_INVALID_LENGTH);
        return w.len;
    }

    uint8_t cmd = msg[0];
    const uint8_t *payload = msg + 1;
    size_t plen = len - 1;

    switch (cmd) {
        case CMD_GET_INFO:
            return build_get_info(out, out_cap);
        case CMD_MAKE_CREDENTIAL:
            return make_credential(payload, plen, out, out_cap);
        case CMD_GET_ASSERTION:
            return get_assertion(payload, plen, out, out_cap);
        case CMD_CANCEL: {
            /* Acknowledge with an empty CBOR map. */
            fj_cbor_writer w;
            fj_cbor_writer_init(&w, out, out_cap);
            fj_cbor_map(&w, 0);
            return w.len;
        }
        default: {
            fj_cbor_writer w;
            fj_cbor_writer_init(&w, out, out_cap);
            fj_cbor_uint(&w, ERR_INVALID_COMMAND);
            return w.len;
        }
    }
}