// Copyright (c) 2026 maro (mail@mgoth.de)
// This software is released under the GNU General Public License v3.0. See LICENSE file for details.
// This header needs to maintain in any file it is present in, as per the GPL license terms.

// mbedTLS platform port: 256KB static heap, RDRAND entropy, ticks timing

#include "mbedtls/mbedtls_config.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/memory_buffer_alloc.h"
#include "mbedtls/timing.h"
#include <stdint.h>
#include <stddef.h>

uint32_t wm_get_ticks(void);

#define TLS_HEAP_SIZE (512 * 1024)
static unsigned char g_tls_heap[TLS_HEAP_SIZE];

// returns 1 if RDRAND worked
static int rdrand64(uint64_t *out) {
    unsigned char ok;
    __asm__ volatile (
        "rdrand %0\n\t"
        "setc   %1\n\t"
        : "=r"(*out), "=qm"(ok)
        :
        : "cc"
    );
    return ok;
}

int mbedtls_hardware_poll(void *data, unsigned char *output, size_t len, size_t *olen) {
    (void)data;
    size_t i = 0;

    while (i + 8 <= len) {
        uint64_t val;
        int tries = 10;
        while (tries-- > 0 && !rdrand64(&val))
            ;
        if (tries < 0) {
            /* RDRAND failed — mix ticks + stack addr as weak fallback */
            val  = (uint64_t)wm_get_ticks();
            val ^= (uint64_t)(uintptr_t)output;
            val ^= (uint64_t)(uintptr_t)&val;
        }
        int b;
        for (b = 0; b < 8; b++)
            output[i++] = (val >> (b * 8)) & 0xFF;
    }

    // remaining bytes (less than 8)
    if (i < len) {
        uint64_t val;
        size_t shift;
        if (!rdrand64(&val))
            val = (uint64_t)wm_get_ticks();
        while (i < len) {
            shift = (i % 8) * 8;
            output[i] = (val >> shift) & 0xFF;
            i++;
        }
    }

    *olen = len;
    return 0;
}

unsigned long mbedtls_timing_get_timer(struct mbedtls_timing_hr_time *val, int reset) {
    uint64_t now = (uint64_t)wm_get_ticks();
    int i;
    if (reset) {
        for (i = 0; i < 8; i++)
            val->opaque[i] = (now >> (i * 8)) & 0xFF;
        return 0;
    }
    uint64_t start = 0;
    for (i = 0; i < 8; i++)
        start |= ((uint64_t)val->opaque[i]) << (i * 8);
    return (unsigned long)(now - start);
}

void tls_port_init(void) {
    mbedtls_memory_buffer_alloc_init(g_tls_heap, TLS_HEAP_SIZE);
}
