/*
 * Fjaeger - CTAP2 authenticator operations (see ctap2.h).
 */
#include <string.h>

#include "ctap2.h"
#include "cbor.h"
#include "crypto.h"
#include "keys.h"
#include "pin.h"
#include "state.h"
#include "rgb_led.h"

/* ------------------------------------------------------------------ */
/* CTAP2 command bytes                                                 */
/* ------------------------------------------------------------------ */
#define CMD_MAKE_CREDENTIAL 0x01
#define CMD_MAKE_CREDENTIAL 0x01
#define CMD_GET_ASSERTION   0x02
#define CMD_GET_INFO        0x04
#define CMD_CLIENT_PIN      0x06
#define CMD_GET_NEXT_ASSERTION 0x08
#define CMD_CREDENTIAL_MGMT 0x0A

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
#define ERR_NO_CREDENTIALS    0x2e
#define ERR_PUAT_REQUIRED     0x2f
#define ERR_PIN_AUTH_INVALID  0x31
#define ERR_PIN_INVALID       0x32
#define ERR_PIN_BLOCKED       0x34

/* CTAP2 request / response map keys */
#define K_CLIENT_DATA_HASH 0x01
#define K_RP              0x02
#define K_USER            0x03
#define K_PUB_KEY_CRED_PARAMS 0x04
#define K_EXCLUDE_LIST     0x05
#define K_EXTENSIONS       0x06
#define K_OPTIONS          0x07
#define K_RP_ID            0x01
#define K_CLIENT_DATA_HASH2 0x02
#define K_ALLOW_LIST       0x03
#define K_USER_OPTION      0x05
#define K_CREDENTIAL       0x01
#define K_AUTH_DATA        0x02
#define K_SIGNATURE        0x03
#define K_USER_ENTITY      0x04

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

/* State for discovering resident credentials across multiple getAssertion
 * responses (numberOfCredentials / getNextAssertion). Valid only while an
 * RP-based discovery is in progress within the active profile. */
static bool discovery_active = false;
static unsigned discovery_index = 0;
static unsigned discovery_total = 0;
static uint8_t discovery_rp_hash[FJ_HASH_LEN];
static uint8_t discovery_client_data_hash[FJ_HASH_LEN];

/* Stateful credential-management enumeration. A new enumerateRPsBegin /
 * enumerateCredentialsBegin resets the corresponding cursor; the matching
 * GetNext* subcommand advances it. Only resident credentials in the active
 * profile are ever enumerated. */
static unsigned cm_rp_index = 0;       /* index of next RP to return */
static unsigned cm_rp_count = 0;       /* total RPs in the active profile */
static unsigned cm_cred_index = 0;     /* index of next credential to return */
static unsigned cm_cred_count = 0;     /* total credentials for the RP */
static uint8_t cm_rp_hash[FJ_HASH_LEN];/* RP being enumerated */

/* authenticatorCredentialManagement subcommands */
#define CM_GET_METADATA              0x01
#define CM_ENUM_RPS_BEGIN            0x02
#define CM_ENUM_RPS_NEXT             0x03
#define CM_ENUM_CREDS_BEGIN          0x04
#define CM_ENUM_CREDS_NEXT           0x05

/* authenticatorCredentialManagement response keys */
#define CM_RSP_RP           0x03
#define CM_RSP_RP_HASH      0x04
#define CM_RSP_TOTAL_RPS    0x05
#define CM_RSP_USER         0x06
#define CM_RSP_CRED_ID      0x07
#define CM_RSP_PUBKEY       0x08
#define CM_RSP_TOTAL_CREDS  0x09

/* authenticatorCredentialManagement request keys */
#define CM_REQ_SUBCOMMAND   0x01
#define CM_REQ_SUBPARAMS    0x02
#define CM_REQ_PIN_AUTH     0x04

/* Shared synchronous crypto workspace.  Keeping these buffers out of the
 * 4 KiB RP2350 stack leaves room for mbedTLS's bignum/ECDSA call chain. */
static uint8_t work_pub[65];
static uint8_t work_authdata[FJ_AUTH_DATA_MAX];
static uint8_t work_to_sign[FJ_AUTH_DATA_MAX + FJ_HASH_LEN];
static uint8_t work_signature_raw[64];
static uint8_t work_signature_der[80];
static uint8_t work_priv[FJ_ECDSA_KEY_BYTES];  /* decrypted private scalar */

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
    discovery_active = false;
    cm_rp_index = cm_rp_count = 0;
    cm_cred_index = cm_cred_count = 0;
}

/* Drop any in-progress resident-credential discovery. The active profile is
 * kept in the credential store (keys.c), so a profile switch from the console
 * must invalidate the buffered selection here. */
void fj_ctap2_invalidate_discovery(void) {
    discovery_active = false;
    /* A new active profile also invalidates credential-management cursors so
     * the next enumeration cannot leak credentials from the old profile. */
    cm_rp_index = cm_rp_count = 0;
    cm_cred_index = cm_cred_count = 0;
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
    memset(work_priv, 0, sizeof(work_priv));
    sign_counter = 0;
    ctap2_dirty = false;
    discovery_active = false;
    cm_rp_index = cm_rp_count = 0;
    cm_cred_index = cm_cred_count = 0;
}

void fj_ctap2_forget_profile(unsigned profile_id) {
    bool removed = false;
    for (unsigned i = 0; i < FJ_CTAP2_CREDS; i++) {
        if (creds[i].in_use && creds[i].profile_id == profile_id) {
            memset(&creds[i], 0, sizeof(fj_ctap2_cred_t));
            removed = true;
        }
    }
    /* A changed credential set invalidates any in-progress discovery. */
    discovery_active = false;
    cm_rp_index = cm_rp_count = 0;
    cm_cred_index = cm_cred_count = 0;
    /* Persist the purge so a stale deferred flush cannot resurrect the
     * erased credentials; the persistent store was already updated by the
     * profile erase. */
    if (removed) ctap2_dirty = true;
}

/* Build the AES-GCM AAD that binds a credential's immutable, security-
 * relevant metadata to its encrypted private key (FJ-006). Any change to
 * these fields invalidates the GCM tag, so e.g. moving a credential between
 * profiles or altering its RP binding fails decryption. Mutable fields are
 * deliberately excluded. Returns the AAD length. */
static size_t cred_build_aad(const fj_ctap2_cred_t *cr, uint8_t aad[128]) {
    uint8_t ver = 1;
    size_t p = 0;
    aad[p++] = ver;
    memcpy(aad + p, cr->credential_id, FJ_CRED_ID_LEN); p += FJ_CRED_ID_LEN;
    aad[p++] = cr->profile_id;
    memcpy(aad + p, cr->rp_id_hash, FJ_HASH_LEN); p += FJ_HASH_LEN;
    memcpy(aad + p, cr->public_key, 65); p += 65;
    aad[p++] = cr->resident ? 1 : 0;
    return p;
}

/* Decrypt a credential's private scalar (wrapped by the CWK at rest) into
 * 'out' (FJ_ECDSA_KEY_BYTES bytes). Returns false when the device is not
 * unlocked with the CWK available or when the GCM tag fails to authenticate
 * (which also detects tampering with the credential's bound metadata).
 * The caller must wipe the output buffer after signing. */
static bool cred_decrypt_private(const fj_ctap2_cred_t *cr, uint8_t out[FJ_ECDSA_KEY_BYTES]) {
    uint8_t cwk[FJ_ECDSA_KEY_BYTES];
    if (!fj_state_cwk(cwk)) return false;
    uint8_t aad[128];
    size_t aad_len = cred_build_aad(cr, aad);
    bool ok = fj_aes_gcm_decrypt_with_aad(cwk, cr->private_key_nonce,
                                          cr->private_key_tag,
                                          aad, aad_len,
                                          cr->private_key_enc,
                                          FJ_ECDSA_KEY_BYTES, out);
    memset(aad, 0, sizeof(aad));
    memset(cwk, 0, sizeof(cwk));
    return ok;
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

/* Return the nth resident credential in the active profile that matches
 * rp_id_hash. Used to discover resident (discoverable) credentials without
 * an allowList. Returns NULL when there are no more matches. */
static fj_ctap2_cred_t *find_resident_by_rp_index(const uint8_t rp_id_hash[FJ_HASH_LEN],
                                                  unsigned idx) {
    unsigned active = fj_keys_active_profile();
    unsigned seen = 0;
    for (unsigned i = 0; i < FJ_CTAP2_CREDS; i++) {
        if (creds[i].in_use && creds[i].resident &&
            creds[i].profile_id == active &&
            memcmp(creds[i].rp_id_hash, rp_id_hash, FJ_HASH_LEN) == 0) {
            if (seen == idx) return &creds[i];
            seen++;
        }
    }
    return NULL;
}

/* Count resident credentials in the active profile matching rp_id_hash. */
static unsigned count_resident_by_rp(const uint8_t rp_id_hash[FJ_HASH_LEN]) {
    unsigned active = fj_keys_active_profile();
    unsigned n = 0;
    for (unsigned i = 0; i < FJ_CTAP2_CREDS; i++) {
        if (creds[i].in_use && creds[i].resident &&
            creds[i].profile_id == active &&
            memcmp(creds[i].rp_id_hash, rp_id_hash, FJ_HASH_LEN) == 0)
            n++;
    }
    return n;
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

    fj_cbor_map(&w, 6);

    /* versions */
    fj_cbor_uint(&w, 0x01);
    fj_cbor_array(&w, 1);
    fj_cbor_tstr(&w, "FIDO_2_0");

    /* extensions: credProtect is advertised so OpenSSH permits creating
     * resident keys. The policy is accepted but not enforced on-device. */
    fj_cbor_uint(&w, 0x02);
    fj_cbor_array(&w, 1);
    fj_cbor_tstr(&w, "credProtect");

    /* aaguid */
    fj_cbor_uint(&w, 0x03);
    uint8_t aaguid[16];
    memset(aaguid, 0, sizeof(aaguid));
    fj_cbor_bstr(&w, aaguid, sizeof(aaguid));

    /* Resident (discoverable) credentials, client PIN and credential
     * management are supported. pinUvAuthToken is deliberately NOT advertised
     * so clients (e.g. libfido2) use the CTAP2.0 getPinToken flow.
     *
     * NOTE: CTAP2 requires canonical CBOR map key ordering: string keys are
     * sorted by length ascending, then bytewise. "credMgmt" (8) must precede
     * "clientPin" (9). */
    fj_cbor_uint(&w, 0x04);
    fj_cbor_map(&w, 5);
    fj_cbor_tstr(&w, "rk");   fj_cbor_bool(&w, true);
    fj_cbor_tstr(&w, "up");   fj_cbor_bool(&w, true);
    fj_cbor_tstr(&w, "uv");   fj_cbor_bool(&w, false);
    fj_cbor_tstr(&w, "credMgmt"); fj_cbor_bool(&w, true);
    fj_cbor_tstr(&w, "clientPin"); fj_cbor_bool(&w, true);

    /* maxMsgSize */
    fj_cbor_uint(&w, 0x05);
    fj_cbor_uint(&w, 1200);

    /* pinUvAuthProtocols: [1] */
    fj_cbor_uint(&w, 0x06);
    fj_cbor_array(&w, 1);
    fj_cbor_uint(&w, FJ_PIN_PROTOCOL);

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
    uint8_t rp_id[FJ_RP_MAX]; size_t rp_id_len = 0;
    uint8_t user_id[FJ_USER_ID_LEN]; size_t user_id_len = 0;
    bool have_client_hash = false, have_rp = false, have_user_id = false;
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
                /* Parse the user map and keep its "id" field. Resident
                 * credentials must store the user id so they can be
                 * discovered and matched by RP later. */
                if (val.type != FJ_CBOR_MAP) goto bad_param;
                size_t upairs = (size_t)val.val;
                for (size_t j = 0; j < upairs; j++) {
                    fj_cbor_item uk, uv;
                    if (!fj_cbor_next(&r, &uk)) goto bad_param;
                    char ukey_name[16];
                    if (!read_text(&r, &uk, ukey_name, sizeof(ukey_name)))
                        goto bad_param;
                    if (!fj_cbor_next(&r, &uv)) goto bad_param;
                    if (strcmp(ukey_name, "id") == 0 && uv.type == FJ_CBOR_BSTR) {
                        size_t n = 0;
                        if (fj_cbor_read_bytes(&r, &uv, user_id, FJ_USER_ID_LEN, &n) &&
                            n > 0 && n <= FJ_USER_ID_LEN) {
                            user_id_len = n;
                            have_user_id = true;
                        } else if (!fj_cbor_skip(&r, &uv)) {
                            goto bad_param;
                        }
                    } else {
                        if (!fj_cbor_skip(&r, &uv)) goto bad_param;
                    }
                }
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
    /* Resident credentials require a user id so they can be discovered and
     * matched by RP later. */
    if (resident && !have_user_id) return ctap_error(out, cap, ERR_MISSING_PARAMETER);

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

    /* Generate the private scalar in the RAM workspace, derive and persist
     * the public key, then encrypt the scalar at rest with the CWK so only
     * the ciphertext, nonce and tag ever reach flash. */
    uint8_t cwk[FJ_ECDSA_KEY_BYTES];
    if (!fj_state_cwk(cwk)) {
        /* No credential wrapping key: the device was not unlocked with the
         * device PIN, so a private key cannot be protected at rest. */
        return ctap_error(out, cap, ERR_OPERATION_DENIED);
    }
    if (!fj_ecdsa_generate_private(work_priv)) {
        cr->in_use = false;
        return ctap_error(out, cap, ERR_INVALID_PARAMETER);
    }
    if (!fj_ecdsa_pubkey(work_priv, cr->public_key)) {
        cr->in_use = false;
        memset(work_priv, 0, sizeof(work_priv));
        return ctap_error(out, cap, ERR_INVALID_PARAMETER);
    }
    /* Bind the private key to its immutable metadata via AES-GCM AAD, so
     * later tampering with those fields fails decryption (FJ-006). */
    memcpy(cr->rp_id_hash, rp_id_hash, FJ_HASH_LEN);
    fj_random(cr->private_key_nonce, sizeof(cr->private_key_nonce));
    uint8_t aad[128];
    size_t aad_len = cred_build_aad(cr, aad);
    if (!fj_aes_gcm_encrypt_with_aad(cwk, cr->private_key_nonce, aad, aad_len,
                                     work_priv, FJ_ECDSA_KEY_BYTES,
                                     cr->private_key_enc, cr->private_key_tag)) {
        cr->in_use = false;
        memset(work_priv, 0, sizeof(work_priv));
        return ctap_error(out, cap, ERR_INVALID_PARAMETER);
    }
    memset(aad, 0, sizeof(aad));
    memset(work_priv, 0, sizeof(work_priv));
    memset(cwk, 0, sizeof(cwk));

    if (resident) {
        memcpy(cr->rp, rp_id, rp_id_len);
        cr->rp_len = (uint8_t)rp_id_len;
        memcpy(cr->user_id, user_id, user_id_len);
        cr->user_id_len = (uint8_t)user_id_len;
        cr->resident = true;
    }
    cr->in_use = true;

    /* authData uses the stored public key. */
    memcpy(work_pub, cr->public_key, sizeof(work_pub));

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

    /* Resolve the credential. With an allowList we use its id (active profile
     * only). Without an allowList we look up the first resident (discoverable)
     * credential in the active profile whose RP matches; if several exist we
     * report numberOfCredentials and let getNextAssertion iterate the rest. */
    fj_ctap2_cred_t *cr = NULL;
    bool multiple = false;
    if (have_allow) {
        cr = find_cred_by_id_active(allow_id);
        if (cr && memcmp(cr->rp_id_hash, rp_id_hash, FJ_HASH_LEN) != 0)
            cr = NULL;
        if (!cr) return ctap_error(out, cap, ERR_NOT_ALLOWED);
    } else {
        cr = find_resident_by_rp_index(rp_id_hash, 0);
        /* A discovery (no allowList) getAssertion that finds no resident
         * credential must report CTAP2_ERR_NO_CREDENTIALS, not NOT_ALLOWED:
         * libfido2 passes the raw byte through unchanged and OpenSSH's
         * key_lookup treats 0x2E == FIDO_ERR_NO_CREDENTIALS as "no duplicate,
         * proceed with enrollment". */
        if (!cr) return ctap_error(out, cap, ERR_NO_CREDENTIALS);
        multiple = (count_resident_by_rp(rp_id_hash) > 1);
        if (multiple) {
            /* Start a discovery sequence for getNextAssertion. The client
             * data hash is retained so every assertion in the sequence signs
             * the same authData || clientDataHash message. */
            discovery_active = true;
            discovery_index = 0;
            discovery_total = count_resident_by_rp(rp_id_hash);
            memcpy(discovery_rp_hash, rp_id_hash, FJ_HASH_LEN);
            memcpy(discovery_client_data_hash, client_data_hash, FJ_HASH_LEN);
        }
    }

    /* authData. */
    size_t ad_len = build_ga_authdata(work_authdata, sizeof(work_authdata),
                                      rp_id_hash);
    if (ad_len == 0) goto bad_param;

    /* Signed data: authData || clientDataHash. */
    memcpy(work_to_sign, work_authdata, ad_len);
    memcpy(work_to_sign + ad_len, client_data_hash, FJ_HASH_LEN);
    uint8_t sig_digest[FJ_HASH_LEN];
    fj_sha256(work_to_sign, ad_len + FJ_HASH_LEN, sig_digest);

    size_t signature_len = 0;
    /* Decrypt the private scalar, sign, then wipe the plaintext. */
    if (!cred_decrypt_private(cr, work_priv) ||
        !fj_ecdsa_sign(work_priv, sig_digest, work_signature_raw) ||
        !fj_ecdsa_signature_der(work_signature_raw, work_signature_der,
                                sizeof(work_signature_der), &signature_len)) {
        memset(work_priv, 0, sizeof(work_priv));
        goto bad_param;
    }
    memset(work_priv, 0, sizeof(work_priv));
    fj_led_sign();

    /* Response: credential, authData, signature, the user entity for resident
     * credentials (key 0x04 is a map, not a raw handle) and, when more
     * matching credentials follow, the number of credentials. */
    bool resident = (cr->resident && cr->user_id_len > 0);
    size_t npairs = 3 + (resident ? 1 : 0) + (multiple ? 1 : 0);
    if (cap < 2) return 0;
    out[0] = 0;
    fj_cbor_writer w;
    fj_cbor_writer_init(&w, out + 1, cap - 1);

    fj_cbor_map(&w, npairs);

    /* credential: {id: bstr, type: "public-key"}.  CTAP2 requires
     * deterministic CBOR ordering, so the shorter text key comes first. */
    fj_cbor_uint(&w, K_CREDENTIAL);
    fj_cbor_map(&w, 2);
    fj_cbor_tstr(&w, "id"); fj_cbor_bstr(&w, cr->credential_id, FJ_CRED_ID_LEN);
    fj_cbor_tstr(&w, "type"); fj_cbor_tstr(&w, "public-key");

    fj_cbor_uint(&w, K_AUTH_DATA); fj_cbor_bstr(&w, work_authdata, ad_len);
    fj_cbor_uint(&w, K_SIGNATURE);
    fj_cbor_bstr(&w, work_signature_der, signature_len);
    /* userEntity (key 0x04): {"id": <user id>}. We only persist the user id,
     * so the entity carries just that. */
    if (resident) {
        fj_cbor_uint(&w, 0x04);
        fj_cbor_map(&w, 1);
        fj_cbor_tstr(&w, "id"); fj_cbor_bstr(&w, cr->user_id, cr->user_id_len);
    }
    if (multiple) {
        fj_cbor_uint(&w, 0x05);
        fj_cbor_uint(&w, discovery_total);
    }

    if (!fj_cbor_ok(&w)) return 0;
    return w.len + 1;

missing:
    return ctap_error(out, cap, ERR_MISSING_PARAMETER);
bad_param:
    return ctap_error(out, cap, ERR_INVALID_PARAMETER);
}

/* ------------------------------------------------------------------ */
/* GetNextAssertion (0x08)                                             */
/* ------------------------------------------------------------------ */
/* Continue a resident-credential discovery started by a getAssertion
 * without an allowList. Returns the next matching credential, or
 * ERR_NOT_ALLOWED once the sequence is exhausted. */
static size_t get_next_assertion(uint8_t *out, size_t cap) {
    if (!discovery_active)
        return ctap_error(out, cap, ERR_NOT_ALLOWED);

    /* Bump the index past the credential returned by the previous call. */
    discovery_index++;

    if (discovery_index >= discovery_total) {
        /* Sequence finished; subsequent calls must fail. */
        discovery_active = false;
        return ctap_error(out, cap, ERR_NOT_ALLOWED);
    }

    fj_ctap2_cred_t *cr = find_resident_by_rp_index(discovery_rp_hash,
                                                    discovery_index);
    if (!cr) {
        discovery_active = false;
        return ctap_error(out, cap, ERR_NOT_ALLOWED);
    }

    if (fj_state_get() != FJ_STATE_UNLOCKED) {
        discovery_active = false;
        return ctap_error(out, cap, ERR_OPERATION_DENIED);
    }

    size_t ad_len = build_ga_authdata(work_authdata, sizeof(work_authdata),
                                      discovery_rp_hash);
    if (ad_len == 0) goto bad_param;

    /* Signed data: authData || clientDataHash, reusing the hash captured by
     * the originating getAssertion so the whole discovery sequence signs the
     * same message (getNextAssertion carries no clientDataHash itself). */
    memcpy(work_to_sign, work_authdata, ad_len);
    memcpy(work_to_sign + ad_len, discovery_client_data_hash, FJ_HASH_LEN);
    uint8_t sig_digest[FJ_HASH_LEN];
    fj_sha256(work_to_sign, ad_len + FJ_HASH_LEN, sig_digest);

    size_t signature_len = 0;
    /* Decrypt the private scalar, sign, then wipe the plaintext. */
    if (!cred_decrypt_private(cr, work_priv) ||
        !fj_ecdsa_sign(work_priv, sig_digest, work_signature_raw) ||
        !fj_ecdsa_signature_der(work_signature_raw, work_signature_der,
                                sizeof(work_signature_der), &signature_len)) {
        memset(work_priv, 0, sizeof(work_priv));
        goto bad_param;
    }
    memset(work_priv, 0, sizeof(work_priv));
    fj_led_sign();

    bool resident = (cr->resident && cr->user_id_len > 0);
    if (cap < 2) return 0;
    out[0] = 0;
    fj_cbor_writer w;
    fj_cbor_writer_init(&w, out + 1, cap - 1);
    fj_cbor_map(&w, resident ? 4 : 3);

    fj_cbor_uint(&w, K_CREDENTIAL);
    fj_cbor_map(&w, 2);
    fj_cbor_tstr(&w, "id"); fj_cbor_bstr(&w, cr->credential_id, FJ_CRED_ID_LEN);
    fj_cbor_tstr(&w, "type"); fj_cbor_tstr(&w, "public-key");

    fj_cbor_uint(&w, K_AUTH_DATA); fj_cbor_bstr(&w, work_authdata, ad_len);
    fj_cbor_uint(&w, K_SIGNATURE);
    fj_cbor_bstr(&w, work_signature_der, signature_len);
    if (resident) {
        /* userEntity (key 0x04): {"id": <user id>}. */
        fj_cbor_uint(&w, 0x04);
        fj_cbor_map(&w, 1);
        fj_cbor_tstr(&w, "id"); fj_cbor_bstr(&w, cr->user_id, cr->user_id_len);
    }

    if (!fj_cbor_ok(&w)) return 0;
    return w.len + 1;

bad_param:
    discovery_active = false;
    return ctap_error(out, cap, ERR_INVALID_PARAMETER);
}

/* ------------------------------------------------------------------ */
/* authenticatorCredentialManagement (0x0A)                            */
/* ------------------------------------------------------------------ */
/* Every lookup is restricted to resident credentials in the active
 * profile, so enumeration never reveals credentials from another profile. */

static bool rp_hash_seen(const uint8_t rp_hash[FJ_HASH_LEN],
                         const uint8_t seen[][FJ_HASH_LEN], unsigned n) {
    for (unsigned i = 0; i < n; i++)
        if (memcmp(seen[i], rp_hash, FJ_HASH_LEN) == 0) return true;
    return false;
}

/* Number of distinct RP hashes among resident creds in the active profile. */
static unsigned count_distinct_rps_active(void) {
    unsigned active = fj_keys_active_profile();
    uint8_t seen[FJ_CTAP2_CREDS][FJ_HASH_LEN];
    unsigned n = 0;
    for (unsigned i = 0; i < FJ_CTAP2_CREDS; i++) {
        if (creds[i].in_use && creds[i].resident && creds[i].profile_id == active &&
            !rp_hash_seen(creds[i].rp_id_hash, seen, n))
            memcpy(seen[n++], creds[i].rp_id_hash, FJ_HASH_LEN);
    }
    return n;
}

/* Return the idx-th distinct RP hash in the active profile, if any. */
static bool rp_hash_at_index(unsigned idx, uint8_t out[FJ_HASH_LEN]) {
    unsigned active = fj_keys_active_profile();
    uint8_t seen[FJ_CTAP2_CREDS][FJ_HASH_LEN];
    unsigned n = 0, found = 0;
    for (unsigned i = 0; i < FJ_CTAP2_CREDS; i++) {
        if (creds[i].in_use && creds[i].resident && creds[i].profile_id == active &&
            !rp_hash_seen(creds[i].rp_id_hash, seen, n)) {
            memcpy(seen[n], creds[i].rp_id_hash, FJ_HASH_LEN);
            if (found == idx) { memcpy(out, seen[n], FJ_HASH_LEN); return true; }
            found++;
            n++;
        }
    }
    return false;
}

/* First resident credential in the active profile with the given RP hash
 * (used to recover the clear-text RP id and name for an RP entity). */
static fj_ctap2_cred_t *first_resident_for_rp(const uint8_t rp_hash[FJ_HASH_LEN]) {
    unsigned active = fj_keys_active_profile();
    for (unsigned i = 0; i < FJ_CTAP2_CREDS; i++) {
        if (creds[i].in_use && creds[i].resident && creds[i].profile_id == active &&
            memcmp(creds[i].rp_id_hash, rp_hash, FJ_HASH_LEN) == 0)
            return &creds[i];
    }
    return NULL;
}

/* Write a user entity map: {"id": user_id}. */
static void write_user_entity(fj_cbor_writer *w, const fj_ctap2_cred_t *cr) {
    fj_cbor_map(w, 1);
    fj_cbor_tstr(w, "id");
    fj_cbor_bstr(w, cr->user_id, cr->user_id_len);
}

/* Write a PublicKeyCredentialDescriptor: {"id":..., "type":"public-key"}. */
static void write_cred_descriptor(fj_cbor_writer *w, const fj_ctap2_cred_t *cr) {
    fj_cbor_map(w, 2);
    fj_cbor_tstr(w, "id");
    fj_cbor_bstr(w, cr->credential_id, FJ_CRED_ID_LEN);
    fj_cbor_tstr(w, "type"); fj_cbor_tstr(w, "public-key");
}

/* Encode one credentialInfo into the writer: user, credentialID, publicKey,
 * and (for the Begin response) totalCredentials. */
static bool write_credential_info(fj_cbor_writer *w, const fj_ctap2_cred_t *cr,
                                  bool with_total, unsigned total) {
    /* The public key is stored alongside the (wrapped) private key so
     * credential management can expose it without decrypting the private
     * scalar. */
    memcpy(work_pub, cr->public_key, sizeof(work_pub));
    uint8_t cose[128];
    size_t clen = encode_cose_key(cose, sizeof(cose), work_pub);
    if (clen == 0) return false;

    fj_cbor_uint(w, CM_RSP_USER);
    write_user_entity(w, cr);
    fj_cbor_uint(w, CM_RSP_CRED_ID);
    write_cred_descriptor(w, cr);
    fj_cbor_uint(w, CM_RSP_PUBKEY);
    if (clen <= w->cap - w->len) { memcpy(w->buf + w->len, cose, clen); w->len += clen; }
    if (with_total) {
        fj_cbor_uint(w, CM_RSP_TOTAL_CREDS);
        fj_cbor_uint(w, total);
    }
    return true;
}

/* Parse subCommandParams {1: rpIDHash} and copy the hash out. */
static bool parse_rp_hash_param(fj_cbor_reader *r, fj_cbor_item *item,
                                uint8_t rp_hash[FJ_HASH_LEN]) {
    if (item->type != FJ_CBOR_MAP) return false;
    size_t pairs = (size_t)item->val;
    for (size_t i = 0; i < pairs; i++) {
        fj_cbor_item k, v;
        if (!fj_cbor_next(r, &k)) return false;
        if (!fj_cbor_next(r, &v)) return false;
        if (k.type == FJ_CBOR_UINT && k.val == 0x01) {
            size_t n = 0;
            if (v.type != FJ_CBOR_BSTR ||
                !fj_cbor_read_bytes(r, &v, rp_hash, FJ_HASH_LEN, &n) ||
                n != FJ_HASH_LEN)
                return false;
        } else {
            if (!fj_cbor_skip(r, &v)) return false;
        }
    }
    return true;
}

static size_t cm_get_metadata(uint8_t *out, size_t cap) {
    unsigned active = fj_keys_active_profile();
    unsigned total = 0;
    for (unsigned i = 0; i < FJ_CTAP2_CREDS; i++)
        if (creds[i].in_use && creds[i].resident && creds[i].profile_id == active)
            total++;
    if (cap < 2) return 0;
    out[0] = 0;
    fj_cbor_writer w;
    fj_cbor_writer_init(&w, out + 1, cap - 1);
    fj_cbor_map(&w, 2);
    fj_cbor_uint(&w, 0x01); fj_cbor_uint(&w, total);   /* existingResidentCredentialsCount */
    fj_cbor_uint(&w, 0x02); fj_cbor_uint(&w, FJ_CTAP2_CREDS - total); /* remaining */
    if (!fj_cbor_ok(&w)) return 0;
    return w.len + 1;
}

static size_t cm_enumerate_rps_begin(uint8_t *out, size_t cap) {
    cm_rp_index = 0;
    cm_rp_count = count_distinct_rps_active();
    if (cm_rp_count == 0) return ctap_error(out, cap, ERR_NO_CREDENTIALS);

    uint8_t hash[FJ_HASH_LEN];
    if (!rp_hash_at_index(0, hash)) return ctap_error(out, cap, ERR_NO_CREDENTIALS);
    fj_ctap2_cred_t *cr = first_resident_for_rp(hash);
    if (!cr) return ctap_error(out, cap, ERR_NO_CREDENTIALS);
    cm_rp_index = 1;

    if (cap < 2) return 0;
    out[0] = 0;
    fj_cbor_writer w;
    fj_cbor_writer_init(&w, out + 1, cap - 1);
    fj_cbor_map(&w, 3);
    fj_cbor_uint(&w, CM_RSP_RP);
    fj_cbor_map(&w, 1);
    fj_cbor_tstr(&w, "id");
    fj_cbor_tstr(&w, (const char *)cr->rp);
    fj_cbor_uint(&w, CM_RSP_RP_HASH);
    fj_cbor_bstr(&w, hash, FJ_HASH_LEN);
    fj_cbor_uint(&w, CM_RSP_TOTAL_RPS);
    fj_cbor_uint(&w, cm_rp_count);
    if (!fj_cbor_ok(&w)) return 0;
    return w.len + 1;
}

static size_t cm_enumerate_rps_next(uint8_t *out, size_t cap) {
    if (cm_rp_index >= cm_rp_count) return ctap_error(out, cap, ERR_NO_CREDENTIALS);
    uint8_t hash[FJ_HASH_LEN];
    if (!rp_hash_at_index(cm_rp_index, hash))
        return ctap_error(out, cap, ERR_NO_CREDENTIALS);
    fj_ctap2_cred_t *cr = first_resident_for_rp(hash);
    if (!cr) return ctap_error(out, cap, ERR_NO_CREDENTIALS);
    cm_rp_index++;

    if (cap < 2) return 0;
    out[0] = 0;
    fj_cbor_writer w;
    fj_cbor_writer_init(&w, out + 1, cap - 1);
    fj_cbor_map(&w, 2);
    fj_cbor_uint(&w, CM_RSP_RP);
    fj_cbor_map(&w, 1);
    fj_cbor_tstr(&w, "id");
    fj_cbor_tstr(&w, (const char *)cr->rp);
    fj_cbor_uint(&w, CM_RSP_RP_HASH);
    fj_cbor_bstr(&w, hash, FJ_HASH_LEN);
    if (!fj_cbor_ok(&w)) return 0;
    return w.len + 1;
}

static size_t cm_enumerate_creds_begin(const uint8_t rp_hash[FJ_HASH_LEN],
                                       uint8_t *out, size_t cap) {
    memcpy(cm_rp_hash, rp_hash, FJ_HASH_LEN);
    cm_cred_index = 0;
    cm_cred_count = count_resident_by_rp(rp_hash);
    if (cm_cred_count == 0) return ctap_error(out, cap, ERR_NO_CREDENTIALS);

    fj_ctap2_cred_t *cr = find_resident_by_rp_index(rp_hash, 0);
    if (!cr) return ctap_error(out, cap, ERR_NO_CREDENTIALS);
    cm_cred_index = 1;

    if (cap < 2) return 0;
    out[0] = 0;
    fj_cbor_writer w;
    fj_cbor_writer_init(&w, out + 1, cap - 1);
    fj_cbor_map(&w, 4);
    if (!write_credential_info(&w, cr, true, cm_cred_count))
        return ctap_error(out, cap, ERR_INVALID_PARAMETER);
    if (!fj_cbor_ok(&w)) return 0;
    return w.len + 1;
}

static size_t cm_enumerate_creds_next(uint8_t *out, size_t cap) {
    if (cm_cred_index >= cm_cred_count) return ctap_error(out, cap, ERR_NO_CREDENTIALS);
    fj_ctap2_cred_t *cr = find_resident_by_rp_index(cm_rp_hash, cm_cred_index);
    if (!cr) return ctap_error(out, cap, ERR_NO_CREDENTIALS);
    cm_cred_index++;

    if (cap < 2) return 0;
    out[0] = 0;
    fj_cbor_writer w;
    fj_cbor_writer_init(&w, out + 1, cap - 1);
    fj_cbor_map(&w, 3);
    if (!write_credential_info(&w, cr, false, 0))
        return ctap_error(out, cap, ERR_INVALID_PARAMETER);
    if (!fj_cbor_ok(&w)) return 0;
    return w.len + 1;
}

static size_t credential_management(const uint8_t *req, size_t len,
                                    uint8_t *out, size_t cap) {
    fj_cbor_reader r;
    fj_cbor_reader_init(&r, req, len);

    fj_cbor_item root;
    if (!fj_cbor_next(&r, &root) || root.type != FJ_CBOR_MAP)
        return ctap_error(out, cap, ERR_INVALID_PARAMETER);

    size_t pairs = (size_t)root.val;
    unsigned subcmd = 0xff;
    bool have_subcmd = false;
    uint8_t pin_auth[16];
    bool have_pin_auth = false;
    uint8_t rp_hash[FJ_HASH_LEN];
    bool have_rp_hash = false;

    for (size_t i = 0; i < pairs; i++) {
        fj_cbor_item k, v;
        if (!fj_cbor_next(&r, &k) || k.type != FJ_CBOR_UINT)
            return ctap_error(out, cap, ERR_INVALID_PARAMETER);
        if (!fj_cbor_next(&r, &v))
            return ctap_error(out, cap, ERR_INVALID_PARAMETER);
        switch (k.val) {
            case CM_REQ_SUBCOMMAND:
                if (v.type != FJ_CBOR_UINT) return ctap_error(out, cap, ERR_INVALID_PARAMETER);
                subcmd = (unsigned)v.val;
                have_subcmd = true;
                break;
            case CM_REQ_PIN_AUTH: {
                size_t n = 0;
                if (v.type != FJ_CBOR_BSTR ||
                    !fj_cbor_read_bytes(&r, &v, pin_auth, sizeof(pin_auth), &n) ||
                    n != sizeof(pin_auth))
                    return ctap_error(out, cap, ERR_INVALID_PARAMETER);
                have_pin_auth = true;
                break;
            }
            case CM_REQ_SUBPARAMS:
                if (!parse_rp_hash_param(&r, &v, rp_hash))
                    return ctap_error(out, cap, ERR_INVALID_PARAMETER);
                have_rp_hash = true;
                break;
            default:
                if (!fj_cbor_skip(&r, &v)) return ctap_error(out, cap, ERR_INVALID_PARAMETER);
                break;
        }
    }

    if (!have_subcmd) return ctap_error(out, cap, ERR_MISSING_PARAMETER);

    switch (subcmd) {
        case CM_GET_METADATA: {
            /* pinAuth = authenticate(pinToken, 0x01). */
            if (!have_pin_auth) return ctap_error(out, cap, ERR_PUAT_REQUIRED);
            uint8_t msg = 0x01;
            if (!fj_pin_verify_auth(&msg, 1, pin_auth))
                return ctap_error(out, cap, ERR_PIN_AUTH_INVALID);
            return cm_get_metadata(out, cap);
        }
        case CM_ENUM_RPS_BEGIN: {
            if (!have_pin_auth) return ctap_error(out, cap, ERR_PUAT_REQUIRED);
            uint8_t msg = 0x02;
            if (!fj_pin_verify_auth(&msg, 1, pin_auth))
                return ctap_error(out, cap, ERR_PIN_AUTH_INVALID);
            return cm_enumerate_rps_begin(out, cap);
        }
        case CM_ENUM_RPS_NEXT:
            return cm_enumerate_rps_next(out, cap);
        case CM_ENUM_CREDS_BEGIN: {
            if (!have_pin_auth) return ctap_error(out, cap, ERR_PUAT_REQUIRED);
            if (!have_rp_hash) return ctap_error(out, cap, ERR_MISSING_PARAMETER);
            /* pinAuth = authenticate(pinToken, 0x04 || {1: rpIDHash}).
             * The canonical encoding of {1: rpIDHash} is A1 01 58 20 || hash. */
            uint8_t msg[1 + 4 + FJ_HASH_LEN];
            msg[0] = 0x04;
            msg[1] = 0xA1; msg[2] = 0x01; msg[3] = 0x58; msg[4] = 0x20;
            memcpy(msg + 5, rp_hash, FJ_HASH_LEN);
            if (!fj_pin_verify_auth(msg, sizeof(msg), pin_auth))
                return ctap_error(out, cap, ERR_PIN_AUTH_INVALID);
            return cm_enumerate_creds_begin(rp_hash, out, cap);
        }
        case CM_ENUM_CREDS_NEXT:
            return cm_enumerate_creds_next(out, cap);
        default:
            return ctap_error(out, cap, ERR_INVALID_COMMAND);
    }
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
        case CMD_GET_NEXT_ASSERTION:
            return get_next_assertion(out, out_cap);
        case CMD_CLIENT_PIN:
            return fj_ctap2_client_pin(payload, plen, out, out_cap);
        case CMD_CREDENTIAL_MGMT:
            return credential_management(payload, plen, out, out_cap);
        default: {
            return ctap_error(out, out_cap, ERR_INVALID_COMMAND);
        }
    }
}
