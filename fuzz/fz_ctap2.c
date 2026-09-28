/* Fuzz the CTAP2 dispatcher and its command parsers (FJ-N009): any byte
 * stream is fed to every command (makeCredential, getAssertion, clientPin,
 * credentialManagement, getNextAssertion, getInfo) under a populated store
 * so the deep sign/enumeration paths are reached. Must never OOB/hang. */
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include "cbor.h"
#include "crypto.h"
#include "ctap2.h"
#include "keys.h"
#include "state.h"

#define FZ_CAP 2048u

extern fj_ctap2_cred_t fuzz_persisted[];

/* Build a valid resident makeCredential request and run it once so the live
 * store has a resident credential (getAssertion / credMgmt then go deep). */
static void fz_seed_resident(void) {
    uint8_t req[256];
    size_t p = 0;
    req[p++] = 0x01;                   /* authenticatorMakeCredential */
    req[p++] = 0xa6;                   /* map(6) */
    req[p++] = 0x01; req[p++] = 0x58; req[p++] = 0x20;
    for (int i = 0; i < 32; i++) req[p++] = (uint8_t)(0xAB + i);
    req[p++] = 0x02; req[p++] = 0xa1; req[p++] = 0x62;
    req[p++] = 'i'; req[p++] = 'd'; req[p++] = 0x64;
    req[p++] = 's'; req[p++] = 's'; req[p++] = 'h'; req[p++] = ':';
    req[p++] = 0x03; req[p++] = 0xa3;
    req[p++] = 0x62; req[p++] = 'i'; req[p++] = 'd'; req[p++] = 0x58; req[p++] = 0x20;
    for (int i = 0; i < 32; i++) req[p++] = 0xCD;
    req[p++] = 0x64; memcpy(req + p, "name", 4); p += 4;
    req[p++] = 0x67; memcpy(req + p, "espegro", 7); p += 7;
    req[p++] = 0x6b; memcpy(req + p, "displayName", 11); p += 11;
    req[p++] = 0x67; memcpy(req + p, "espegro", 7); p += 7;
    req[p++] = 0x04; req[p++] = 0x81; req[p++] = 0xa2;
    req[p++] = 0x63; memcpy(req + p, "alg", 3); p += 3;
    req[p++] = 0x26;                 /* alg -7 */
    req[p++] = 0x64; memcpy(req + p, "type", 4); p += 4;
    req[p++] = 0x6a; memcpy(req + p, "public-key", 10); p += 10;
    req[p++] = 0x05; req[p++] = 0x80;
    req[p++] = 0x07; req[p++] = 0xa1; req[p++] = 0x62;
    req[p++] = 'r'; req[p++] = 'k'; req[p++] = 0xf5;
    {
        uint8_t out[768];
        fj_ctap2_dispatch(req, p, out, sizeof(out));
        fj_ctap2_task();             /* persist so reload paths are exercised */
    }
}

int fz_ctap2(const uint8_t *data, size_t size) {
    static bool seeded = false;
    uint8_t msg[2 + FZ_CAP];
    uint8_t out[768];
    size_t plen;
    uint8_t cmd;

    if (size == 0) return 0;
    if (!seeded) { fz_seed_resident(); seeded = true; }
    if (size > FZ_CAP) size = FZ_CAP;

    plen = size - 1;
    if (plen > FZ_CAP) plen = FZ_CAP;
    memcpy(msg + 1, data + 1, plen);

    /* Exercise every command with the same (payload, mutating) input. */
    for (cmd = 0x01; cmd <= 0x0A; cmd++) {
        msg[0] = cmd;
        fj_ctap2_dispatch(msg, 1 + plen, out, sizeof(out));
    }
    return 0;
}

/* libFuzzer entry point (built with -fsanitize=fuzzer). */
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    return fz_ctap2(data, size);
}
