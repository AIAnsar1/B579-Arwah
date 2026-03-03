#pragma once


#ifndef B579_PLATFORM_MEMORY_H
#define B579_PLATFORM_MEMORY_H

#include "b579_platform_types.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ══════════════════════════════════════════
 *  Safe Allocators
 *
 *  ALWAYS use these instead of raw malloc/calloc/free.
 *  They provide:
 *    - NULL checks on allocation failure
 *    - Zero-initialization (calloc behavior)
 *    - Zero-on-free (security)
 *    - Allocation tracking (debug builds)
 * ══════════════════════════════════════════ 
 */

/* Allocate `size` bytes, zeroed. Returns NULL on failure. */
void *b579_malloc(size_t size);

/* Allocate array of `count` elements of `size` bytes each, zeroed. */
/* Checks for overflow: count * size must not wrap around. */
void *b579_calloc(size_t count, size_t size);

/* Resize allocation. New bytes are zeroed. */
/* If ptr is NULL, behaves like b579_malloc. */
void *b579_realloc(void *ptr, size_t old_size, size_t new_size);

/* Free memory. Zeroes `size` bytes before freeing. */
/* If ptr is NULL, does nothing (safe to call). */
void b579_free(void *ptr, size_t size);

/* Duplicate `size` bytes from `src`. Returns new allocation. */
void *b579_memdup(const void *src, size_t size);

/* ══════════════════════════════════════════
 *  Locked Memory
 *
 *  Prevent memory from being swapped to disk.
 *  Critical for:
 *    - Encryption keys
 *    - SYN cookie secrets
 *    - Sensitive scan results
 * ══════════════════════════════════════════ 
 */

/* Allocate and lock memory (mlock/VirtualLock) */
void *b579_malloc_locked(size_t size);

/* Unlock and free locked memory */
void b579_free_locked(void *ptr, size_t size);

/* ══════════════════════════════════════════
 *  Aligned Memory
 *
 *  Needed for:
 *    - SIMD operations (AVX2 needs 32-byte alignment)
 *    - Avoiding cache line splits
 *    - DMA buffers
 * ══════════════════════════════════════════ 
 */

/* Allocate memory aligned to `alignment` bytes */
/* alignment must be power of 2 */
void *b579_malloc_aligned(size_t size, size_t alignment);

/* Free aligned memory */
void b579_free_aligned(void *ptr);

/* ══════════════════════════════════════════
 *  Secure Memory Operations
 * ══════════════════════════════════════════ 
 */

/* Zero memory that compiler cannot optimize away */
/* Unlike memset(p,0,n) which compiler may remove if */
/* it thinks nobody reads the memory afterwards */
void b579_memzero_secure(void *ptr, size_t size);

/* ══════════════════════════════════════════
 *  Debug: Memory Statistics
 *
 *  Only active in debug builds (#ifndef NDEBUG).
 *  Tracks total allocations, frees, and bytes.
 *  Useful for detecting leaks.
 * ══════════════════════════════════════════ 
 */

typedef struct {
    uint64_t total_allocs;      /* Total allocation calls */
    uint64_t total_frees;       /* Total free calls */
    uint64_t bytes_allocated;   /* Currently allocated bytes */
    uint64_t peak_allocated;    /* Peak allocated bytes ever */
} b579_mem_stats_t;

/* Get current memory statistics (debug builds only) */
b579_mem_stats_t b579_mem_get_stats(void);

/* Print memory statistics to stderr */
void b579_mem_print_stats(void);

#ifdef __cplusplus
}
#endif

#endif /* B579_PLATFORM_MEMORY_H */














































