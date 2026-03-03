#pragma once


#ifndef B579_PLATFORM_TYPES_H
#define B579_PLATFORM_TYPES_H

#include <stdint.h>
#include <stddef.h>

#include "b579_platform_detect.h"
/*
 * B-579 Arwah — Common Types
 *
 * Portable type definitions used across all C libraries.
 * Includes sized integers, boolean, result codes.
 *
 * Pattern: Single Source of Truth (DRY)
 *          All libraries use these types instead of
 *          defining their own.
 */

/* ══════════════════════════════════════════
 *  Boolean — portable across C standards
 * ══════════════════════════════════════════ 
 */
/* ══════════════════════════════════════════
 *  Boolean — portable across C standards
 * ══════════════════════════════════════════ */

#if defined(__STDC_VERSION__) && __STDC_VERSION__ >= 202311L
    /* C23: bool is built-in keyword */
#elif defined(__STDC_VERSION__) && __STDC_VERSION__ >= 199901L
    #include <stdbool.h>
#else
    /* Pre-C99: define our own */
    #ifndef __cplusplus
        typedef int bool;
        #define true  1
        #define false 0
    #endif
#endif


/* ══════════════════════════════════════════
 *  Result Code — every function returns this
 *
 *  Convention:
 *    0          = success (B579_OK)
 *    negative   = error
 *    positive   = success with info (e.g., bytes read)
 *
 *  Pattern: Defensive Programming
 *           Never silently ignore errors.
 * ══════════════════════════════════════════ */

typedef int b579_result_t;

#define B579_OK             0      /* Success */
#define B579_ERR           -1      /* Generic error */
#define B579_ERR_NULL      -2      /* NULL pointer passed */
#define B579_ERR_NOMEM     -3      /* Memory allocation failed */
#define B579_ERR_PERM      -4      /* Permission denied (not root?) */
#define B579_ERR_NOSYS     -5      /* Not implemented on this platform */
#define B579_ERR_INVAL     -6      /* Invalid argument */
#define B579_ERR_RANGE     -7      /* Value out of range */
#define B579_ERR_TIMEOUT   -8      /* Operation timed out */
#define B579_ERR_BUSY      -9      /* Resource busy */
#define B579_ERR_IO        -10     /* I/O error */

/* Check if result is success */
#define B579_IS_OK(r)       ((r) >= 0)
#define B579_IS_ERR(r)      ((r) < 0)


/* ══════════════════════════════════════════
 *  Defensive Macros — prevent shooting yourself in the foot
 *
 *  DRY: write the check ONCE as a macro,
 *       use it in EVERY function.
 *
 *  Usage:
 *    b579_result_t my_func(void *ptr, int count) {
 *        B579_CHECK_NULL(ptr);
 *        B579_CHECK_RANGE(count, 1, 1000);
 *        // ... safe to use ptr and count here
 *    }
 * ══════════════════════════════════════════ */

/* Return error if pointer is NULL */
#define B579_CHECK_NULL(ptr)                                        \
    do {                                                            \
        if (B579_UNLIKELY((ptr) == NULL)) {                         \
            return B579_ERR_NULL;                                   \
        }                                                           \
    } while (0)

/* Return error if value is out of [min, max] range */
#define B579_CHECK_RANGE(val, min_val, max_val)                     \
    do {                                                            \
        if (B579_UNLIKELY((val) < (min_val) || (val) > (max_val))) {\
            return B579_ERR_RANGE;                                  \
        }                                                           \
    } while (0)

/* Return error if condition is false */
#define B579_CHECK(cond, err_code)                                  \
    do {                                                            \
        if (B579_UNLIKELY(!(cond))) {                               \
            return (err_code);                                      \
        }                                                           \
    } while (0)


/* ══════════════════════════════════════════
 *  Safe Pointer Macros
 * ══════════════════════════════════════════ */

/* Zero memory and set pointer to NULL after free */
#define B579_SAFE_FREE(ptr)                                         \
    do {                                                            \
        if ((ptr) != NULL) {                                        \
            free(ptr);                                              \
            (ptr) = NULL;                                           \
        }                                                           \
    } while (0)

/* Array length (only for stack arrays, NOT pointers!) */
#define B579_ARRAY_LEN(arr)   (sizeof(arr) / sizeof((arr)[0]))

/* Min / Max */
#define B579_MIN(a, b)        (((a) < (b)) ? (a) : (b))
#define B579_MAX(a, b)        (((a) > (b)) ? (a) : (b))
#define B579_CLAMP(val, lo, hi) B579_MAX((lo), B579_MIN((val), (hi)))


#endif /* B579_PLATFORM_TYPES_H */






