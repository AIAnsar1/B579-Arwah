


#include "include/b579_platform_internal.h"

/* System includes for platform-specific memory ops */
#ifdef B579_OS_UNIX
    #include <sys/mman.h>   /* mlock, munlock */
    #include <unistd.h>
#endif

#ifdef B579_OS_WINDOWS
    #ifndef WIN32_LEAN_AND_MEAN
        #define WIN32_LEAN_AND_MEAN
    #endif
    #include <windows.h>
#endif


/* ══════════════════════════════════════════
 *  Debug: Allocation Tracking
 *
 *  Only active when NDEBUG is NOT defined.
 *  Uses atomics for thread safety.
 * ══════════════════════════════════════════ */

#ifndef NDEBUG

static b579_atomic_u64 stat_allocs    = 0;
static b579_atomic_u64 stat_frees     = 0;
static b579_atomic_u64 stat_bytes_now = 0;
static b579_atomic_u64 stat_bytes_peak = 0;

static void track_alloc(size_t size) 
{
    b579_atomic_inc(&stat_allocs);
    uint64_t current = b579_atomic_add(&stat_bytes_now, size) + size;
    /* Update peak (simple, may lose updates under contention — acceptable) */
    uint64_t peak = b579_atomic_load(&stat_bytes_peak);

    if (current > peak) 
    {
        b579_atomic_store(&stat_bytes_peak, current);
    }
}

static void track_free(size_t size) 
{
    b579_atomic_inc(&stat_frees);
    b579_atomic_sub(&stat_bytes_now, size);
}

#else
    #define track_alloc(size)  ((void)0)
    #define track_free(size)   ((void)0)
#endif


/* ══════════════════════════════════════════
 *  Secure Zero
 *
 *  memset(ptr, 0, n) can be optimized away by the compiler
 *  if it determines nobody reads the memory afterwards.
 *  This version cannot be optimized away.
 * ══════════════════════════════════════════ 
 */

void b579_memzero_secure(void *ptr, size_t size) 
{
    if (!ptr || size == 0)
    {
        return;
    }

#if defined(B579_OS_WINDOWS)
    SecureZeroMemory(ptr, size);

#elif defined(__STDC_LIB_EXT1__)
    /* C11 Annex K */
    memset_s(ptr, size, 0, size);

#else
    /*
     * volatile prevents compiler from optimizing out the memset.
     * This is the most portable approach.
     */
    volatile unsigned char *p = (volatile unsigned char *)ptr;
    while (size--) 
    {
        *p++ = 0;
    }
#endif
}


/* ══════════════════════════════════════════
 *  Safe Allocators
 * ══════════════════════════════════════════ 
 */

void *b579_malloc(size_t size) 
{
    if (size == 0)
    {
        return NULL;
    }

    /* calloc zeroes memory — always safe */
    void *ptr = calloc(1, size);
    if (!ptr) 
    {
        b579_error_set(B579_ERR_NOMEM,"allocation failed: %zu bytes", size);
        return NULL;
    }
    track_alloc(size);
    return ptr;
}

void *b579_calloc(size_t count, size_t size) {
    if (count == 0 || size == 0)
    {
        return NULL;
    }

    /* Overflow check: count * size must not wrap */
    if (count > SIZE_MAX / size) 
    {
        b579_error_set(B579_ERR_RANGE,"calloc overflow: %zu * %zu", count, size);
        return NULL;
    }
    void *ptr = calloc(count, size);

    if (!ptr) 
    {
        b579_error_set(B579_ERR_NOMEM,"calloc failed: %zu * %zu bytes", count, size);
        return NULL;
    }
    track_alloc(count * size);
    return ptr;
}

void *b579_realloc(void *ptr, size_t old_size, size_t new_size) 
{
    if (new_size == 0) 
    {
        b579_free(ptr, old_size);
        return NULL;
    }

    if (!ptr) 
    {
        return b579_malloc(new_size);
    }
    void *new_ptr = realloc(ptr, new_size);

    if (!new_ptr) 
    {
        b579_error_set(B579_ERR_NOMEM,"realloc failed: %zu → %zu bytes", old_size, new_size);
        return NULL; /* old ptr is still valid! */
    }

    /* Zero new bytes if we grew */
    if (new_size > old_size) 
    {
        memset((unsigned char *)new_ptr + old_size, 0, new_size - old_size);
    }
    track_free(old_size);
    track_alloc(new_size);
    return new_ptr;
}

void b579_free(void *ptr, size_t size) 
{
    if (!ptr)
    {
        return;
    }
    /* Zero before freeing — prevent data leaks */
    b579_memzero_secure(ptr, size);
    free(ptr);
    track_free(size);
}

void *b579_memdup(const void *src, size_t size) {
    if (!src || size == 0)
    {
         return NULL;
    }
    void *copy = b579_malloc(size);

    if (copy) 
    {
        memcpy(copy, src, size);
    }
    return copy;
}


/* ══════════════════════════════════════════
 *  Locked Memory (non-swappable)
 * ══════════════════════════════════════════ 
 */

void *b579_malloc_locked(size_t size) 
{
    void *ptr = b579_malloc(size);
    if (!ptr)
    {
        return NULL;
    }
    b579_result_t r = b579_mem_lock_os(ptr, size);

    if (B579_IS_ERR(r)) 
    {
        B579_DBG("mlock failed for %zu bytes (may need root)", size);
        /* Don't fail — return unlocked memory with a warning */
    }
    return ptr;
}

void b579_free_locked(void *ptr, size_t size) 
{
    if (!ptr)
    {
        return;
    }
    b579_memzero_secure(ptr, size);
    b579_mem_unlock_os(ptr, size);
    free(ptr);
    track_free(size);
}


/* ══════════════════════════════════════════
 *  Aligned Memory
 * ══════════════════════════════════════════ 
 */

void *b579_malloc_aligned(size_t size, size_t alignment) 
{
    if (size == 0)
    {
        return NULL;
    }

    /* Alignment must be power of 2 */
    if (alignment == 0 || (alignment & (alignment - 1)) != 0) 
    {
        b579_error_set(B579_ERR_INVAL, "alignment %zu is not power of 2", alignment);
        return NULL;
    }
    void *ptr = b579_mem_aligned_alloc_os(size, alignment);

    if (!ptr) 
    {
        b579_error_set(B579_ERR_NOMEM,"aligned alloc failed: %zu bytes, align %zu", size, alignment);
        return NULL;
    }
    /* Zero the memory */
    memset(ptr, 0, size);
    track_alloc(size);
    return ptr;
}

void b579_free_aligned(void *ptr) 
{
    if (!ptr) return;
    b579_mem_aligned_free_os(ptr);
    /* Note: can't track_free without knowing size */
}


/* ══════════════════════════════════════════
 *  OS-Specific: Lock / Unlock / Aligned
 * ══════════════════════════════════════════ 
 */

#ifdef B579_OS_UNIX

b579_result_t b579_mem_lock_os(void *ptr, size_t size) 
{
    if (mlock(ptr, size) != 0) {
        b579_error_set_errno("mlock");
        return B579_ERR_PERM;
    }
    return B579_OK;
}

b579_result_t b579_mem_unlock_os(void *ptr, size_t size) 
{
    munlock(ptr, size);
    return B579_OK;
}

void *b579_mem_aligned_alloc_os(size_t size, size_t alignment) 
{
    void *ptr = NULL;

    if (posix_memalign(&ptr, alignment, size) != 0) 
    {
        return NULL;
    }
    return ptr;
}

void b579_mem_aligned_free_os(void *ptr) 
{
    free(ptr); /* posix_memalign uses regular free */
}

#endif /* B579_OS_UNIX */


#ifdef B579_OS_WINDOWS

b579_result_t b579_mem_lock_os(void *ptr, size_t size) 
{
    if (!VirtualLock(ptr, size)) 
    {
        b579_error_set_win32("VirtualLock");
        return B579_ERR_PERM;
    }
    return B579_OK;
}

b579_result_t b579_mem_unlock_os(void *ptr, size_t size) 
{
    VirtualUnlock(ptr, size);
    return B579_OK;
}

void *b579_mem_aligned_alloc_os(size_t size, size_t alignment) 
{
    return _aligned_malloc(size, alignment);
}

void b579_mem_aligned_free_os(void *ptr) 
{
    _aligned_free(ptr);
}

#endif /* B579_OS_WINDOWS */


/* ══════════════════════════════════════════
 *  Debug: Statistics
 * ══════════════════════════════════════════ */

b579_mem_stats_t b579_mem_get_stats(void) 
{
    b579_mem_stats_t stats;
    memset(&stats, 0, sizeof(stats));

#ifndef NDEBUG
    stats.total_allocs = b579_atomic_load(&stat_allocs);
    stats.total_frees = b579_atomic_load(&stat_frees);
    stats.bytes_allocated = b579_atomic_load(&stat_bytes_now);
    stats.peak_allocated = b579_atomic_load(&stat_bytes_peak);
#endif

    return stats;
}

void b579_mem_print_stats(void) 
{
#ifndef NDEBUG
    b579_mem_stats_t s = b579_mem_get_stats();
    fprintf(stderr,
            "\n"
            "══════════════════════════════════════\n"
            "  B-579 Memory Statistics\n"
            "══════════════════════════════════════\n"
            "  Allocations:   %llu\n"
            "  Frees:         %llu\n"
            "  Leaked:        %llu calls\n"
            "  Current bytes: %llu\n"
            "  Peak bytes:    %llu\n"
            "══════════════════════════════════════\n",
            (unsigned long long)s.total_allocs,
            (unsigned long long)s.total_frees,
            (unsigned long long)(s.total_allocs - s.total_frees),
            (unsigned long long)s.bytes_allocated,
            (unsigned long long)s.peak_allocated);
#else
    fprintf(stderr, "[B579] Memory stats not available in release build\n");
#endif
}