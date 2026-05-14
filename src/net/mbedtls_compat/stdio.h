// Copyright (c) 2026 maro (mail@mgoth.de)
// This software is released under the GNU General Public License v3.0. See LICENSE file for details.
// This header needs to maintain in any file it is present in, as per the GPL license terms.

// stdio stub for mbedTLS — only snprintf/vsnprintf are actually used
#ifndef _BOREDOS_COMPAT_STDIO_H
#define _BOREDOS_COMPAT_STDIO_H

#include <stddef.h>
#include <stdarg.h>

int snprintf(char *buf, size_t size, const char *fmt, ...);
int vsnprintf(char *buf, size_t size, const char *fmt, va_list ap);

// mbedtls debug output goes nowhere in kernel context
static inline int printf(const char *fmt, ...) { (void)fmt; return 0; }

typedef struct { int dummy; } FILE;
static inline int fprintf(FILE *f, const char *fmt, ...) {
    (void)f; (void)fmt;
    return 0;
}

#endif
