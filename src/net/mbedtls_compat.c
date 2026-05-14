// Copyright (c) 2026 maro (mail@mgoth.de)
// This software is released under the GNU General Public License v3.0. See LICENSE file for details.
// This header needs to maintain in any file it is present in, as per the GPL license terms.

// freestanding libc stubs for mbedTLS: snprintf, string functions, calloc, abort

#include <stddef.h>
#include <stdint.h>
#include <stdarg.h>

void   *memset(void *s, int c, size_t n);
void   *memcpy(void *dest, const void *src, size_t n);
size_t  strlen(const char *s);
int     strcmp(const char *s1, const char *s2);
char   *strcpy(char *dest, const char *src);

void   *kmalloc(size_t size);
void    kfree(void *ptr);

void abort(void) {
    for (;;) __asm__ volatile ("hlt");
}

void *calloc(size_t nmemb, size_t size) {
    size_t total = nmemb * size;
    if (total == 0) return (void *)1;
    void *p = kmalloc(total);
    if (p) memset(p, 0, total);
    return p;
}

void free(void *ptr) {
    if (ptr) kfree(ptr);
}

char *strncpy(char *dest, const char *src, size_t n) {
    size_t i = 0;
    while (i < n && src[i]) { dest[i] = src[i]; i++; }
    while (i < n) { dest[i] = '\0'; i++; }
    return dest;
}

char *strcat(char *dest, const char *src) {
    char *p = dest + strlen(dest);
    while (*src) *p++ = *src++;
    *p = '\0';
    return dest;
}

char *strncat(char *dest, const char *src, size_t n) {
    char *p = dest + strlen(dest);
    size_t i = 0;
    while (i < n && src[i]) { *p++ = src[i++]; }
    *p = '\0';
    return dest;
}

char *strchr(const char *s, int c) {
    for (; *s; s++)
        if ((unsigned char)*s == (unsigned char)c) return (char *)s;
    if (c == '\0') return (char *)s;
    return NULL;
}

char *strrchr(const char *s, int c) {
    const char *last = NULL;
    for (; *s; s++)
        if ((unsigned char)*s == (unsigned char)c) last = s;
    if (c == '\0') return (char *)s;
    return (char *)last;
}

char *strstr(const char *haystack, const char *needle) {
    if (!*needle) return (char *)haystack;
    for (; *haystack; haystack++) {
        const char *h = haystack, *n = needle;
        while (*h && *n && *h == *n) { h++; n++; }
        if (!*n) return (char *)haystack;
    }
    return NULL;
}

char *strdup(const char *s) {
    size_t len = strlen(s) + 1;
    char *p = kmalloc(len);
    if (p) memcpy(p, s, len);
    return p;
}

unsigned long strtoul(const char *nptr, char **endptr, int base) {
    while (*nptr == ' ' || *nptr == '\t') nptr++;
    if (base == 0) {
        if (nptr[0] == '0' && (nptr[1] == 'x' || nptr[1] == 'X')) { base = 16; nptr += 2; }
        else if (nptr[0] == '0') base = 8;
        else base = 10;
    } else if (base == 16 && nptr[0] == '0' && (nptr[1] == 'x' || nptr[1] == 'X')) {
        nptr += 2;
    }
    unsigned long val = 0;
    const char *start = nptr;
    for (;;) {
        int digit;
        if (*nptr >= '0' && *nptr <= '9')      digit = *nptr - '0';
        else if (*nptr >= 'a' && *nptr <= 'f') digit = *nptr - 'a' + 10;
        else if (*nptr >= 'A' && *nptr <= 'F') digit = *nptr - 'A' + 10;
        else break;
        if (digit >= base) break;
        val = val * (unsigned long)base + (unsigned long)digit;
        nptr++;
    }
    if (endptr) *endptr = (char *)(nptr == start ? start : nptr);
    return val;
}

long strtol(const char *nptr, char **endptr, int base) {
    while (*nptr == ' ' || *nptr == '\t') nptr++;
    int neg = 0;
    if (*nptr == '-') { neg = 1; nptr++; }
    else if (*nptr == '+') { nptr++; }
    unsigned long uval = strtoul(nptr, endptr, base);
    return neg ? -(long)uval : (long)uval;
}

static void _put_char(char **buf, size_t *rem, char c) {
    if (*rem > 1) {
        **buf = c;
        (*buf)++;
        (*rem)--;
    }
}

static void _put_str(char **buf, size_t *rem, const char *s) {
    while (s && *s)
        _put_char(buf, rem, *s++);
}

/* XXX: no %f support — mbedTLS shouldn't need it but keep an eye out */
static void _put_uint(char **buf, size_t *rem, unsigned long long v,
                      int base, int upper, int width, int zero_pad) {
    char tmp[64];
    int  len = 0;
    if (v == 0) { tmp[len++] = '0'; }
    else {
        const char *digits = upper ? "0123456789ABCDEF" : "0123456789abcdef";
        while (v) { tmp[len++] = digits[v % (unsigned)base]; v /= (unsigned)base; }
    }
    char pad = zero_pad ? '0' : ' ';
    while (width > len) { _put_char(buf, rem, pad); width--; }
    for (int i = len - 1; i >= 0; i--)
        _put_char(buf, rem, tmp[i]);
}

int vsnprintf(char *buf, size_t size, const char *fmt, va_list ap) {
    char   *p;
    size_t  rem;

    if (!buf || size == 0) return 0;
    p   = buf;
    rem = size;

    for (; *fmt; fmt++) {
        if (*fmt != '%') { _put_char(&p, &rem, *fmt); continue; }
        fmt++;
        int zero_pad = 0, width = 0;
        if (*fmt == '0') { zero_pad = 1; fmt++; }
        while (*fmt >= '0' && *fmt <= '9') { width = width * 10 + (*fmt - '0'); fmt++; }
        int is_long = 0, is_long_long = 0, is_size = 0;
        if (*fmt == 'l') {
            is_long = 1; fmt++;
            if (*fmt == 'l') { is_long_long = 1; fmt++; }
        } else if (*fmt == 'z') { is_size = 1; fmt++; }

        switch (*fmt) {
        case 'd': case 'i': {
            long long v = is_long_long ? va_arg(ap, long long) :
                          (is_long || is_size) ? va_arg(ap, long) :
                          va_arg(ap, int);
            int neg = 0;
            if (v < 0) { neg = 1; v = -v; if (width) width--; }
            if (neg) _put_char(&p, &rem, '-');
            _put_uint(&p, &rem, (unsigned long long)v, 10, 0, width, zero_pad);
            break;
        }
        case 'u': {
            unsigned long long v = is_long_long ? va_arg(ap, unsigned long long) :
                                   (is_long || is_size) ? va_arg(ap, unsigned long) :
                                   va_arg(ap, unsigned int);
            _put_uint(&p, &rem, v, 10, 0, width, zero_pad);
            break;
        }
        case 'x': case 'X': {
            unsigned long long v = is_long_long ? va_arg(ap, unsigned long long) :
                                   (is_long || is_size) ? va_arg(ap, unsigned long) :
                                   va_arg(ap, unsigned int);
            _put_uint(&p, &rem, v, 16, (*fmt == 'X'), width, zero_pad);
            break;
        }
        case 's': {
            const char *s = va_arg(ap, const char *);
            _put_str(&p, &rem, s ? s : "(null)");
            break;
        }
        case 'c':
            _put_char(&p, &rem, (char)va_arg(ap, int));
            break;
        case 'p': {
            uintptr_t v = (uintptr_t)va_arg(ap, void *);
            _put_char(&p, &rem, '0'); _put_char(&p, &rem, 'x');
            _put_uint(&p, &rem, (unsigned long long)v, 16, 0, 0, 0);
            break;
        }
        case '%':
            _put_char(&p, &rem, '%');
            break;
        default:
            _put_char(&p, &rem, '%');
            _put_char(&p, &rem, *fmt);
            break;
        }
    }
    if (size > 0) *p = '\0';
    return (int)(p - buf);
}

int snprintf(char *buf, size_t size, const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(buf, size, fmt, ap);
    va_end(ap);
    return n;
}

int bored_mbed_printf(const char *fmt, ...) {
    (void)fmt;
    return 0;
}
