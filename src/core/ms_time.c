/*
 * Fjaeger - mbedTLS time source for the Pico.
 *
 * mbedTLS 3.x needs mbedtls_ms_time() (used by TLS/DRBG code). The Pico has
 * no OS time source, so provide one based on the microsecond counter.
 */
#include "mbedtls/platform_util.h"
#include "pico/time.h"

mbedtls_ms_time_t mbedtls_ms_time(void) {
    return (mbedtls_ms_time_t)(time_us_64() / 1000);
}