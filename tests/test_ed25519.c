#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "ed25519.h"

/* Deterministic RNG stub for the generation wrapper. */
void fj_random(void *buf, size_t len) {
    uint8_t *p = (uint8_t *)buf;
    for (size_t i = 0; i < len; i++) p[i] = (uint8_t)i;
}

static uint8_t hex_nibble(char c) {
    if (c >= '0' && c <= '9') return (uint8_t)(c - '0');
    if (c >= 'a' && c <= 'f') return (uint8_t)(c - 'a' + 10);
    assert(!"invalid hex");
    return 0;
}

static void from_hex(const char *hex, uint8_t *out, size_t len) {
    assert(strlen(hex) == len * 2);
    for (size_t i = 0; i < len; i++)
        out[i] = (uint8_t)((hex_nibble(hex[i * 2]) << 4) |
                           hex_nibble(hex[i * 2 + 1]));
}

int main(void) {
    /* RFC 8032 section 7.1, test vector 1: empty message. */
    uint8_t seed[32], expected_public[32], expected_signature[64];
    uint8_t public_key[32], signature[64];
    from_hex("9d61b19deffd5a60ba844af492ec2cc4"
             "4449c5697b326919703bac031cae7f60", seed, sizeof(seed));
    from_hex("d75a980182b10ab7d54bfed3c964073a"
             "0ee172f3daa62325af021a68f707511a", expected_public,
             sizeof(expected_public));
    from_hex("e5564300c360ac729086e2cc806e828a"
             "84877f1eb8e5d974d873e06522490155"
             "5fb8821590a33bacc61e39701cf9b46b"
             "d25bf5f0595bbe24655141438e7a100b", expected_signature,
             sizeof(expected_signature));

    assert(fj_ed25519_public(seed, public_key));
    assert(memcmp(public_key, expected_public, sizeof(public_key)) == 0);
    assert(fj_ed25519_sign(seed, NULL, 0, signature));
    assert(memcmp(signature, expected_signature, sizeof(signature)) == 0);

    uint8_t generated_seed[32], generated_public[32], derived_public[32];
    assert(fj_ed25519_generate(generated_seed, generated_public));
    assert(fj_ed25519_public(generated_seed, derived_public));
    assert(memcmp(generated_public, derived_public, sizeof(generated_public)) == 0);

    puts("ed25519 RFC8032: ok");
    return 0;
}
