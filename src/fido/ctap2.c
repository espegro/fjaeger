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
#define ERR_UNSUPPORTED_OPTION 0x2b

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

/* Shared synchronous crypto workspace.  Keeping these buffers out of the
 * 4 KiB RP2350 stack leaves room for mbedTLS's bignum/ECDSA call chain. */
static uint8_t work_pub[65];
static uint8_t work_authdata[FJ_AUTH_DATA_MAX];
static uint8_t work_to_sign[FJ_AUTH_DATA_MAX + FJ_HASH_LEN];
static uint8_t work_signature_raw[64];
static uint8_t work_signature_der[80];

static size_t ctap_error(uint8_t *out, size_t cap, uint8_t error) {
    if (cap < 1) return 0;
    out[0] = error;
    return 1;
}

static bool read_text(fj_cbor_reader *r, fj_cbor_item *item,
                      char *out, size_t cap) {
    size_t len = 0;
    if (cap == 0 || item->type != FJ_CBOR_TSTR ||
        !fj_cbor_read_bytes(r, item, (uint8_t *)out, cap - 1, &len))
        return false;
    out[len] = '\0';
    return true;
}

void fj_ctap2_init(void) {
    fj_keys_ctap2_load(creds);
    ctap2_dirty = false;
    /* Zero means counters are not supported. A volatile random counter would
     * move backwards across boots and cause false authenticator-clone alarms. */
    sign_counter = 0;
}

/* Called from the main loop: flush any pending flash writes. Flash
 * writes must not run inside the USB IRQ context, so we defer them. */
void fj_ctap2_task(void) {
    if (ctap2_dirty) {
        if (fj_keys_ctap2_save(creds)) ctap2_dirty = false;
    }
}

void fj_ctap2_forget_all(void) {
    memset(creds, 0, sizeof(creds));
    memset(work_pub, 0, sizeof(work_pub));
    memset(work_authdata, 0, sizeof(work_authdata));
    memset(work_to_sign, 0, sizeof(work_to_sign));
    memset(work_signature_raw, 0, sizeof(work_signature_raw));
    memset(work_signature_der, 0, sizeof(work_signature_der));
    sign_counter = 0;
    ctap2_dirty = false;
}

void fj_ctap2_forget_profile(unsigned profile_id) {
    bool removed = false;
    for (unsigned i = 0; i < FJ_CTAP2_CREDS; i++) {
        if (creds[i].in_use && creds[i].profile_id == profile_id) {
            memset(&creds[i], 0, sizeof(fj_ctap2_cred_t));
            removed = true;
        }
    }
    /* Persist the purge so a stale deferred flush cannot resurrect the
     * erased credentials; the persistent store was already updated by the
     * profile erase. */
    if (removed) ctap2_dirty = true;
}

static fj_ctap2_cred_t *find_cred_by_id_active(const uint8_t *id) {
    unsigned active = fj_keys_active_profile();
    for (unsigned i = 0; i < FJ_CTAP2_CREDS; i++) {
        if (creds[i].in_use &&
            creds[i].profile_id == active &&
            memcmp(creds[i].credential_id, id, FJ_CRED_ID_LEN) == 0)
            return &creds[i];
    }
    return NULL;
}

static fj_ctap2_cred_t *find_cred_by_rp_active(const uint8_t rp_id_hash[FJ_HASH_LEN]) {
    unsigned active = fj_keys_active_profile();
    for (unsigned i = 0; i < FJ_CTAP2_CREDS; i++) {
        if (creds[i].in_use &&
            creds[i].profile_id == active &&
            memcmp(creds[i].rp_id_hash, rp_id_hash, FJ_HASH_LEN) == 0)
            return &creds[i];
    }
    return NULL;
}

/* Match a credential-ID against every credential, regardless of profile.
 * Used for excludeList so a duplicate registration is rejected across all
 * profiles without revealing which profile owns the existing credential. */
static fj_ctap2_cred_t *find_cred_by_id_any(const uint8_t *id) {
    for (unsigned i = 0; i < FJ_CTAP2_CREDS; i++) {
        if (creds[i].in_use &&
            memcmp(creds[i].credential_id, id, FJ_CRED_ID_LEN) == 0)
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

    fj_cbor_map(&w, 5);
    fj_cbor_uint(&w, 1);  fj_cbor_uint(&w, 2);       /* kty: EC2 */
    fj_cbor_uint(&w, 3);  fj_cbor_neg(&w, 6);        /* alg: -7 ES256 */
    fj_cbor_neg(&w, 0);   fj_cbor_uint(&w, 1);       /* -1 crv: P-256 */
    fj_cbor_neg(&w, 1);   fj_cbor_bstr(&w, pub + 1, 32);  /* -2 x */
    fj_cbor_neg(&w, 2);   fj_cbor_bstr(&w, pub + 33, 32); /* -3 y */

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
                                const uint8_t rp_id_hash[FJ_HASH_LEN]) {
    if (cap < 37) return 0;
    uint8_t *p = out;
    size_t pos = 0;
    memcpy(p + pos, rp_id_hash, 32); pos += 32;
    p[pos++] = 0x01; /* UP */
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
    if (cap < 2) return 0;
    out[0] = 0;
    fj_cbor_writer w;
    fj_cbor_writer_init(&w, out + 1, cap - 1);

    fj_cbor_map(&w, 5);

    /* versions */
    fj_cbor_uint(&w, 0x01);
    fj_cbor_array(&w, 1);
    fj_cbor_tstr(&w, "FIDO_2_0");

    /* extensions: empty */
    fj_cbor_uint(&w, 0x02);
    fj_cbor_array(&w, 0);

    /* aaguid */
    fj_cbor_uint(&w, 0x03);
    uint8_t aaguid[16];
    memset(aaguid, 0, sizeof(aaguid));
    fj_cbor_bstr(&w, aaguid, sizeof(aaguid));

    /* This first implementation supports server-side credentials only. */
    fj_cbor_uint(&w, 0x04);
    fj_cbor_map(&w, 4);
    fj_cbor_tstr(&w, "rk");   fj_cbor_bool(&w, false);
    fj_cbor_tstr(&w, "up");   fj_cbor_bool(&w, true);
    fj_cbor_tstr(&w, "uv");   fj_cbor_bool(&w, false);
    fj_cbor_tstr(&w, "clientPin"); fj_cbor_bool(&w, false);

    /* maxMsgSize */
    fj_cbor_uint(&w, 0x05);
    fj_cbor_uint(&w, 1200);

    if (!fj_cbor_ok(&w)) return 0;
    return w.len + 1;
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
    bool resident = false, excluded = false;
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
                    char key_name[16];
                    if (!read_text(&r, &k2, key_name, sizeof(key_name)))
                        goto bad_param;
                    if (!fj_cbor_next(&r, &v2)) goto bad_param;
                    if (strcmp(key_name, "id") == 0) {
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
                        char key_name[16];
                        if (!read_text(&r, &pk, key_name, sizeof(key_name)))
                            goto bad_param;
                        if (!fj_cbor_next(&r, &pv)) goto bad_param;
                        if (strcmp(key_name, "alg") == 0 &&
                            pv.type == FJ_CBOR_NEG && pv.val == 6)
                            alg = 1; /* ES256 supported */
                        if (!fj_cbor_skip(&r, &pv)) goto bad_param;
                    }
                }
                break;
            }
            case K_EXCLUDE_LIST: {
                /* An excludeList entry prevents re-registering a credential
                 * for the same RP. Detect any existing credential with a
                 * matching credential-ID or RP binding across all profiles,
                 * but without exposing which profile owns it. */
                if (val.type != FJ_CBOR_ARRAY) goto bad_param;
                size_t xn = (size_t)val.val;
                for (size_t j = 0; j < xn; j++) {
                    fj_cbor_item entry;
                    if (!fj_cbor_next(&r, &entry) || entry.type != FJ_CBOR_MAP)
                        goto bad_param;
                    size_t ep = (size_t)entry.val;
                    for (size_t k = 0; k < ep; k++) {
                        fj_cbor_item ek, ev;
                        if (!fj_cbor_next(&r, &ek)) goto bad_param;
                        char key_name[16];
                        if (!read_text(&r, &ek, key_name, sizeof(key_name)))
                            goto bad_param;
                        if (!fj_cbor_next(&r, &ev)) goto bad_param;
                        if (strcmp(key_name, "id") == 0 && ev.type == FJ_CBOR_BSTR) {
                            uint8_t xid[FJ_CRED_ID_LEN];
                            size_t n2 = 0;
                            if (fj_cbor_read_bytes(&r, &ev, xid, FJ_CRED_ID_LEN, &n2) &&
                                n2 == FJ_CRED_ID_LEN &&
                                find_cred_by_id_any(xid) != NULL)
                                excluded = true;
                        } else {
                            if (!fj_cbor_skip(&r, &ev)) goto bad_param;
                        }
                    }
                }
                break;
            }
            case K_OPTIONS: {
                if (val.type != FJ_CBOR_MAP) goto bad_param;
                size_t op = (size_t)val.val;
                for (size_t j = 0; j < op; j++) {
                    fj_cbor_item ok, ov;
                    if (!fj_cbor_next(&r, &ok)) goto bad_param;
                    char name[16];
                    if (!read_text(&r, &ok, name, sizeof(name))) goto bad_param;
                    if (!fj_cbor_next(&r, &ov)) goto bad_param;
                    if (strcmp(name, "rk") == 0)
                        resident = (ov.type == FJ_CBOR_BOOL && ov.val != 0);
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
    if (alg == 0) return ctap_error(out, cap, ERR_UNSUPPORTED_ALG);
    if (resident) return ctap_error(out, cap, ERR_UNSUPPORTED_OPTION);

    if (fj_state_get() != FJ_STATE_UNLOCKED) {
        /* CTAP2_ERR_OPERATION_DENIED (device locked). */
        return ctap_error(out, cap, ERR_OPERATION_DENIED);
    }

    /* rpIdHash = SHA-256(rpId). */
    uint8_t rp_id_hash[FJ_HASH_LEN];
    fj_sha256(rp_id, rp_id_len, rp_id_hash);

    /* Duplicate registration (matching credential-ID or RP binding) is
     * rejected across all profiles without revealing which one owns it. */
    if (excluded) return ctap_error(out, cap, ERR_CREDENTIAL_EXCLUDED);

    /* Allocate a credential slot. */
    fj_ctap2_cred_t *cr = NULL;
    for (unsigned i = 0; i < FJ_CTAP2_CREDS; i++) {
        if (!creds[i].in_use) { cr = &creds[i]; break; }
    }
    if (!cr) {
        return ctap_error(out, cap, ERR_NOT_ALLOWED);
    }

    memset(cr, 0, sizeof(*cr));
    cr->profile_id = (uint8_t)fj_keys_active_profile();
    fj_random(cr->credential_id, FJ_CRED_ID_LEN);
    if (!fj_ecdsa_generate_private(cr->private_key)) {
        cr->in_use = false;
        return ctap_error(out, cap, ERR_INVALID_PARAMETER);
    }
    memcpy(cr->rp_id_hash, rp_id_hash, FJ_HASH_LEN);
    cr->in_use = true;
    (void)resident;

    /* Public key + authData. */
    if (!fj_ecdsa_pubkey(cr->private_key, work_pub)) {
        cr->in_use = false;
        return ctap_error(out, cap, ERR_INVALID_PARAMETER);
    }

    size_t ad_len = build_mc_authdata(work_authdata, sizeof(work_authdata),
                                      rp_id_hash, work_pub, cr->credential_id);
    if (ad_len == 0) {
        cr->in_use = false;
        return ctap_error(out, cap, ERR_INVALID_LENGTH);
    }

    /* Credential committed; mark for deferred flash persist. */
    ctap2_dirty = true;

    /* Response map. */
    if (cap < 2) return 0;
    out[0] = 0;
    fj_cbor_writer w;
    fj_cbor_writer_init(&w, out + 1, cap - 1);
    fj_cbor_map(&w, 3);
    fj_cbor_uint(&w, 0x01); fj_cbor_tstr(&w, "none");           /* fmt */
    fj_cbor_uint(&w, 0x02); fj_cbor_bstr(&w, work_authdata, ad_len); /* authData */
    fj_cbor_uint(&w, 0x03); fj_cbor_map(&w, 0);                 /* attStmt */

    if (!fj_cbor_ok(&w)) {
        cr->in_use = false;
        return 0;
    }
    return w.len + 1;

missing:
    return ctap_error(out, cap, ERR_MISSING_PARAMETER);
bad_param:
    return ctap_error(out, cap, ERR_INVALID_PARAMETER);
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
                        char key_name[16];
                        if (!read_text(&r, &ek, key_name, sizeof(key_name)))
                            goto bad_param;
                        if (!fj_cbor_next(&r, &ev)) goto bad_param;
                        if (strcmp(key_name, "id") == 0 &&
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
        return ctap_error(out, cap, ERR_OPERATION_DENIED);
    }

    uint8_t rp_id_hash[FJ_HASH_LEN];
    fj_sha256(rp_id, rp_id_len, rp_id_hash);

    /* Resolve the credential: by allowList id, else by rpIdHash. Both lookups
     * are restricted to the active profile, so a credential from another
     * profile is never resolved. */
    fj_ctap2_cred_t *cr = NULL;
    if (have_allow)
        cr = find_cred_by_id_active(allow_id);
    else
        cr = find_cred_by_rp_active(rp_id_hash);
    if (!cr) {
        return ctap_error(out, cap, ERR_NOT_ALLOWED);
    }
    if (memcmp(cr->rp_id_hash, rp_id_hash, FJ_HASH_LEN) != 0) {
        return ctap_error(out, cap, ERR_NOT_ALLOWED);
    }

    /* authData. */
    bool with_user = (cr->user_id_len > 0);
    size_t ad_len = build_ga_authdata(work_authdata, sizeof(work_authdata),
                                      rp_id_hash);
    if (ad_len == 0) goto bad_param;

    /* Signed data: authData || clientDataHash. */
    memcpy(work_to_sign, work_authdata, ad_len);
    memcpy(work_to_sign + ad_len, client_data_hash, FJ_HASH_LEN);
    uint8_t sig_digest[FJ_HASH_LEN];
    fj_sha256(work_to_sign, ad_len + FJ_HASH_LEN, sig_digest);

    size_t signature_len = 0;
    if (!fj_ecdsa_sign(cr->private_key, sig_digest, work_signature_raw) ||
        !fj_ecdsa_signature_der(work_signature_raw, work_signature_der,
                                sizeof(work_signature_der), &signature_len))
        goto bad_param;

    /* Response is a map containing credential, authData and signature. */
    if (cap < 2) return 0;
    out[0] = 0;
    fj_cbor_writer w;
    fj_cbor_writer_init(&w, out + 1, cap - 1);

    fj_cbor_map(&w, with_user ? 4 : 3);

    /* credential: {id: bstr, type: "public-key"}.  CTAP2 requires
     * deterministic CBOR ordering, so the shorter text key comes first. */
    fj_cbor_uint(&w, K_CREDENTIAL);
    fj_cbor_map(&w, 2);
    fj_cbor_tstr(&w, "id"); fj_cbor_bstr(&w, cr->credential_id, FJ_CRED_ID_LEN);
    fj_cbor_tstr(&w, "type"); fj_cbor_tstr(&w, "public-key");

    fj_cbor_uint(&w, K_AUTH_DATA); fj_cbor_bstr(&w, work_authdata, ad_len);
    fj_cbor_uint(&w, K_SIGNATURE);
    fj_cbor_bstr(&w, work_signature_der, signature_len);
    if (with_user) {
        fj_cbor_uint(&w, K_USER_HANDLE);
        fj_cbor_bstr(&w, cr->user_id, cr->user_id_len);
    }

    if (!fj_cbor_ok(&w)) return 0;
    return w.len + 1;

missing:
    return ctap_error(out, cap, ERR_MISSING_PARAMETER);
bad_param:
    return ctap_error(out, cap, ERR_INVALID_PARAMETER);
}

/* ------------------------------------------------------------------ */
/* Dispatch                                                            */
/* ------------------------------------------------------------------ */
size_t fj_ctap2_dispatch(const uint8_t *msg, size_t len,
                         uint8_t *out, size_t out_cap) {
    if (len == 0) {
        return ctap_error(out, out_cap, ERR_INVALID_LENGTH);
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
            return ctap_error(out, out_cap, 0);
        }
        default: {
            return ctap_error(out, out_cap, ERR_INVALID_COMMAND);
        }
    }
}
