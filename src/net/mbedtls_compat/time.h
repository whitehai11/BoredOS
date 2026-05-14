// Copyright (c) 2026 maro (mail@mgoth.de)
// This software is released under the GNU General Public License v3.0. See LICENSE file for details.
// This header needs to maintain in any file it is present in, as per the GPL license terms.

// MBEDTLS_HAVE_TIME is not set so time() is never actually called
// (stub here just in case something pulls the header anyway)
#ifndef _BOREDOS_COMPAT_TIME_H
#define _BOREDOS_COMPAT_TIME_H

#include <stdint.h>

typedef int64_t time_t;

static inline time_t time(time_t *t) {
    if (t) *t = 0;
    return 0;
}

#endif
