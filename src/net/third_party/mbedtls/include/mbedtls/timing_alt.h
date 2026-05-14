/**
 * BoredOS timing alt for mbedTLS.
 * Uses system ticks via sys_system(SYSTEM_CMD_GET_TICKS).
 */
#ifndef MBEDTLS_TIMING_ALT_H
#define MBEDTLS_TIMING_ALT_H

#include <stdint.h>

// Opaque timer struct — stores start tick in first 8 bytes
struct mbedtls_timing_hr_time {
    unsigned char opaque[32];
};

typedef struct mbedtls_timing_delay_context {
    struct mbedtls_timing_hr_time timer;
    uint32_t int_ms;
    uint32_t fin_ms;
} mbedtls_timing_delay_context;

#endif /* MBEDTLS_TIMING_ALT_H */
