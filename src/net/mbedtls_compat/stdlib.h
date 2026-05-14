// Copyright (c) 2026 maro (mail@mgoth.de)
// This software is released under the GNU General Public License v3.0. See LICENSE file for details.
// This header needs to maintain in any file it is present in, as per the GPL license terms.

#ifndef _BOREDOS_COMPAT_STDLIB_H
#define _BOREDOS_COMPAT_STDLIB_H

#include <stddef.h>

#define EXIT_SUCCESS 0
#define EXIT_FAILURE 1

void *calloc(size_t nmemb, size_t size);
void  free(void *ptr);
void  abort(void) __attribute__((noreturn));

unsigned long strtoul(const char *nptr, char **endptr, int base);
long strtol(const char *nptr, char **endptr, int base);
int  atoi(const char *s);

#endif
