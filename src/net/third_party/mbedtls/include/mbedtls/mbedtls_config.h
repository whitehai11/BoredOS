/**
 * mbedTLS configuration for BoredOS
 *
 * Baremetal x86_64, no libc, no OS threads.
 * TLS 1.2 client only (TLS 1.3 requires PSA Crypto, out of scope for now).
 */

#ifndef MBEDTLS_CONFIG_H
#define MBEDTLS_CONFIG_H

/* ----------------------------------------------------------------
 * Platform: no libc, custom alloc
 * ---------------------------------------------------------------- */
#define MBEDTLS_PLATFORM_C
#define MBEDTLS_PLATFORM_MEMORY
#define MBEDTLS_MEMORY_BUFFER_ALLOC_C
#define MBEDTLS_NO_PLATFORM_ENTROPY
/* Prevent platform.h from including stdio.h / stdlib.h (freestanding build) */
#define MBEDTLS_PLATFORM_NO_STD_FUNCTIONS
/* Redirect print functions — our stubs in mbedtls_compat.c handle these */
#define MBEDTLS_PLATFORM_SNPRINTF_MACRO  snprintf
#define MBEDTLS_PLATFORM_VSNPRINTF_MACRO vsnprintf
#define MBEDTLS_PLATFORM_PRINTF_MACRO    bored_mbed_printf
/* Forward-declare bored_mbed_printf so mbedTLS source files can call it
 * via the mbedtls_printf macro without an implicit-declaration error. */
#include <stdarg.h>
int bored_mbed_printf(const char *fmt, ...);

#undef MBEDTLS_FS_IO
#undef MBEDTLS_THREADING_C
#undef MBEDTLS_THREADING_PTHREAD

/* ----------------------------------------------------------------
 * Entropy: RDRAND + ticks (we provide mbedtls_hardware_poll)
 * ---------------------------------------------------------------- */
#define MBEDTLS_ENTROPY_C
#define MBEDTLS_CTR_DRBG_C
#define MBEDTLS_ENTROPY_HARDWARE_ALT

/* ----------------------------------------------------------------
 * TLS 1.2 client only
 * ---------------------------------------------------------------- */
#define MBEDTLS_SSL_TLS_C
#define MBEDTLS_SSL_CLI_C
#define MBEDTLS_SSL_PROTO_TLS1_2
#define MBEDTLS_SSL_KEEP_PEER_CERTIFICATE

/* TLS extensions */
#define MBEDTLS_SSL_SERVER_NAME_INDICATION
#define MBEDTLS_SSL_MAX_FRAGMENT_LENGTH
#define MBEDTLS_SSL_ALPN
#define MBEDTLS_SSL_RENEGOTIATION

/* ----------------------------------------------------------------
 * Cipher suites
 * ---------------------------------------------------------------- */
#define MBEDTLS_AES_C
#define MBEDTLS_GCM_C
#define MBEDTLS_CCM_C
#define MBEDTLS_CHACHA20_C
#define MBEDTLS_POLY1305_C
#define MBEDTLS_CHACHAPOLY_C
#define MBEDTLS_CIPHER_C
#define MBEDTLS_CIPHER_MODE_CBC
#define MBEDTLS_CIPHER_PADDING_PKCS7

/* ----------------------------------------------------------------
 * Key exchange
 * ---------------------------------------------------------------- */
#define MBEDTLS_BIGNUM_C
#define MBEDTLS_RSA_C
#define MBEDTLS_PKCS1_V15
#define MBEDTLS_PKCS1_V21
#define MBEDTLS_ECP_C
#define MBEDTLS_ECDH_C
#define MBEDTLS_ECDSA_C
#define MBEDTLS_ECP_DP_SECP256R1_ENABLED
#define MBEDTLS_ECP_DP_SECP384R1_ENABLED
#define MBEDTLS_ECP_DP_SECP521R1_ENABLED
#define MBEDTLS_KEY_EXCHANGE_ECDHE_RSA_ENABLED
#define MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED
#define MBEDTLS_KEY_EXCHANGE_RSA_ENABLED
#define MBEDTLS_PK_C
#define MBEDTLS_PK_PARSE_C
#define MBEDTLS_PKCS5_C
#define MBEDTLS_DHM_C
#define MBEDTLS_KEY_EXCHANGE_DHE_RSA_ENABLED

/* ----------------------------------------------------------------
 * Hashing
 * ---------------------------------------------------------------- */
#define MBEDTLS_MD_C
#define MBEDTLS_SHA1_C
#define MBEDTLS_SHA224_C
#define MBEDTLS_SHA256_C
#define MBEDTLS_SHA384_C
#define MBEDTLS_SHA512_C
#define MBEDTLS_HKDF_C
#define MBEDTLS_HMAC_DRBG_C

/* ----------------------------------------------------------------
 * X.509 / Certificates
 * ---------------------------------------------------------------- */
#define MBEDTLS_X509_USE_C
#define MBEDTLS_X509_CRT_PARSE_C
#define MBEDTLS_ASN1_PARSE_C
#define MBEDTLS_ASN1_WRITE_C
#define MBEDTLS_OID_C
#define MBEDTLS_PEM_PARSE_C
#define MBEDTLS_BASE64_C

/* ----------------------------------------------------------------
 * Misc
 * ---------------------------------------------------------------- */
#define MBEDTLS_ERROR_C
#define MBEDTLS_TIMING_ALT

/* Buffer sizes */
#define MBEDTLS_SSL_IN_CONTENT_LEN    16384
#define MBEDTLS_SSL_OUT_CONTENT_LEN   16384

/* NOTE: do NOT include check_config.h here.
 * build_info.h includes config_adjust_legacy_crypto.h (which computes
 * MBEDTLS_CAN_ECDH, MBEDTLS_MD_CAN_SHA256, etc.) BEFORE check_config.h.
 * Including check_config.h directly from the config file runs it before
 * those derived macros exist, causing spurious prerequisite errors. */

#endif /* MBEDTLS_CONFIG_H */
