#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "hmac_secret.h"
#include "crypto.h"

/* These vectors do not use randomness; satisfy unrelated crypto wrappers. */
void fj_random(void *buf, size_t len) { memset(buf, 0, len); }

static void unhex(const char *hex, uint8_t *out, size_t len) {
    for (size_t i = 0; i < len; i++) {
        unsigned n;
        assert(sscanf(hex + i * 2, "%2x", &n) == 1);
        out[i] = (uint8_t)n;
    }
}
int main(void) {
    uint8_t shared[32], cred[32], encrypted[64], auth[32], expected[64], out[64];
    for (unsigned i = 0; i < 32; i++) { shared[i] = (uint8_t)i; cred[i] = (uint8_t)(128 + i); }
    unhex("a37edf3f975abaef937b62c78d5bb157a36e5f05ba7cce858453a779401a16dd605f73bd14c46fd8ff6c4459f719fc41cd0f5d50e015d5c54eae44743a955325", encrypted, 64);
    unhex("e6803e4fda7c2accdfd2b93185c9b9aa", auth, 16);
    unhex("2c53740317d6a7bce64786a7becd181f52de9646414e02bad630317c18323f4dad3cd83fc4a87b595d157a1150477e39774f9d41f7505ec81138cec1e11928f3", expected, 64);
    assert(fj_hmac_secret_v1(shared, cred, encrypted, 64, auth, out, sizeof(out)));
    assert(memcmp(out, expected, 64) == 0);
    auth[0] ^= 1;
    memset(out, 0xa5, sizeof(out));
    assert(!fj_hmac_secret_v1(shared, cred, encrypted, 64, auth, out, sizeof(out)));
    for (unsigned i = 0; i < sizeof(out); i++) assert(out[i] == 0xa5);
    assert(!fj_hmac_secret_v1(shared, cred, encrypted, 31, auth, out, sizeof(out)));
    assert(!fj_hmac_secret_v1(shared, cred, encrypted, 64, auth, out, 32));
    assert(fj_hmac_sha256(shared, sizeof(shared), encrypted, 32, auth));
    assert(fj_hmac_secret_v1(shared, cred, encrypted, 32, auth, out, sizeof(out)));
    assert(memcmp(out, expected, 32) == 0);
    puts("hmac-secret protocol 1 vectors: ok");
}
