/**
 * Stub assert.h for BoredOS freestanding mbedTLS build.
 * NDEBUG is implied — assert() is a no-op.
 */
#ifndef _BOREDOS_ASSERT_H
#define _BOREDOS_ASSERT_H

/* In a freestanding kernel build there is no C library, so assert is a
 * compile-time-safe no-op.  mbedTLS only uses assert() for internal
 * invariant checks; disabling them is fine for a production build. */
#define assert(expr) ((void)(expr))

#endif /* _BOREDOS_ASSERT_H */
