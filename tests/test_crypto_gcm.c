#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "crypto.h"

/* crypto.c's asymmetric helpers share the production RNG hook. GCM itself
 * does not use it, but the complete translation unit needs a host-test stub. */
void fj_random(void *buf, size_t len) {
    memset(buf, 0x42, len);
}

static int all_zero(const uint8_t *buf, size_t len) {
    uint8_t acc = 0;
    for (size_t i = 0; i < len; i++) acc |= buf[i];
    return acc == 0;
}

int main(void) {
    const uint8_t key[32] = { 1 };
    const uint8_t nonce[12] = { 2 };
    const uint8_t aad[] = "credential-metadata";
    const uint8_t plaintext[] = "authenticated plaintext";
    uint8_t ciphertext[sizeof(plaintext)];
    uint8_t recovered[sizeof(plaintext)];
    uint8_t tag[16];

    assert(fj_aes_gcm_encrypt_with_aad(key, nonce, aad, sizeof(aad),
                                       plaintext, sizeof(plaintext),
                                       ciphertext, tag));
    memset(recovered, 0xa5, sizeof(recovered));
    assert(fj_aes_gcm_decrypt_with_aad(key, nonce, tag, aad, sizeof(aad),
                                       ciphertext, sizeof(ciphertext),
                                       recovered));
    assert(memcmp(recovered, plaintext, sizeof(plaintext)) == 0);

    tag[0] ^= 1;
    memset(recovered, 0xa5, sizeof(recovered));
    assert(!fj_aes_gcm_decrypt_with_aad(key, nonce, tag, aad, sizeof(aad),
                                        ciphertext, sizeof(ciphertext),
                                        recovered));
    assert(all_zero(recovered, sizeof(recovered)));

    puts("crypto GCM tests passed");
    return 0;
}
