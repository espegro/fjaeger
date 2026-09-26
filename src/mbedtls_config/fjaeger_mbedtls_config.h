/*
 * Fjaeger - mbedTLS configuration (mbedTLS 3.x, Pico port).
 *
 * Starts from the full mbedTLS default configuration and applies the
 * Pico-specific settings required for this device:
 *   - No OS platform entropy source (the RP2350 hardware RNG is used via
 *     pico_mbedtls' mbedtls_hardware_poll).
 *   - Use the RP2350 SHA-256 hardware accelerator.
 *
 * X.509 attestation has been removed (CTAP2 uses attestation format
 * "none"), but the default config keeps the X.509 modules; they are simply
 * unused. This is acceptable given the 16 MB flash.
 */

/* Start from the default mbedTLS 3.x configuration. */
#include "mbedtls/mbedtls_config.h"

/* Use the RP2350 hardware RNG as the only entropy source. */
#define MBEDTLS_NO_PLATFORM_ENTROPY
#define MBEDTLS_ENTROPY_HARDWARE_ALT

/* Use the RP2350 SHA-256 hardware accelerator. */
#define MBEDTLS_SHA256_ALT

/* No OS time source on the Pico: provide mbedtls_ms_time() ourselves
 * (see src/core/ms_time.c) so mbedTLS compiles. */
#define MBEDTLS_PLATFORM_MS_TIME_ALT

/* Timing module only works on Unix/Windows and is only used by TLS/SSL,
 * which this device does not need. */
#undef MBEDTLS_TIMING_C

/* This device is an authenticator: it does not use TLS/SSL, X.509 or PKCS7.
 * Disable the whole TLS stack and its prerequisites so no POSIX filesystem
 * / OS-only code (opendir/readdir in x509_crt.c, timing.c, etc.) is built.
 * CTAP2/U2F only need the crypto primitives (AES-XTS, SHA-256, ECDSA, HKDF). */
#undef MBEDTLS_X509_USE_C
#undef MBEDTLS_X509_CRT_PARSE_C
#undef MBEDTLS_X509_CRL_PARSE_C
#undef MBEDTLS_X509_CSR_PARSE_C
#undef MBEDTLS_X509_CREATE_C
#undef MBEDTLS_X509_CRT_WRITE_C
#undef MBEDTLS_X509_CSR_WRITE_C
#undef MBEDTLS_PKCS7_C
#undef MBEDTLS_SSL_ALL_ALERT_MESSAGES
#undef MBEDTLS_SSL_CONTEXT_SERIALIZATION
#undef MBEDTLS_SSL_ENCRYPT_THEN_MAC
#undef MBEDTLS_SSL_EXTENDED_MASTER_SECRET
#undef MBEDTLS_SSL_KEEP_PEER_CERTIFICATE
#undef MBEDTLS_SSL_RENEGOTIATION
#undef MBEDTLS_SSL_MAX_FRAGMENT_LENGTH
#undef MBEDTLS_SSL_PROTO_TLS1_2
#undef MBEDTLS_SSL_PROTO_TLS1_3
#undef MBEDTLS_SSL_PROTO_DTLS
#undef MBEDTLS_SSL_ALPN
#undef MBEDTLS_SSL_SESSION_TICKETS
#undef MBEDTLS_SSL_SERVER_NAME_INDICATION
#undef MBEDTLS_SSL_CACHE_C
#undef MBEDTLS_SSL_COOKIE_C
#undef MBEDTLS_SSL_TICKET_C
#undef MBEDTLS_SSL_CLI_C
#undef MBEDTLS_SSL_SRV_C
#undef MBEDTLS_SSL_TLS_C
#undef MBEDTLS_NET_C

/* SHA-3 is enabled by the default config but the SDK's pico_mbedtls does
 * not build sha3.c, producing undefined mbedtls_sha3_* symbols. Not needed. */
#undef MBEDTLS_SHA3_C