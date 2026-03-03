

#include "include/b579_platform_internal.h"


/*
 * B-579 Arwah — CPU Dispatcher
 *
 * Delegates to OS-specific implementations.
 * Adds input validation (Defensive Programming).
 *
 * Pattern: Strategy + Guard (validate before delegate)
 */


/* ══════════════════════════════════════════
 *  CPU Information — delegate with caching
 * ══════════════════════════════════════════ 
 */

/* Cache the count — it won't change during runtime */

static int cached_cpu_count = 0;

int b579_cpu_count(void) 
{
    if (cached_cpu_count == 0) 
    {
        cached_cpu_count = b579_cpu_count_os();
        if (cached_cpu_count <= 0) 
        {
            cached_cpu_count = 1; /* fallback: at least 1 core */
        }
        B579_DBG("CPU count: %d", cached_cpu_count);
    }
    return cached_cpu_count;
}


int b579_cpu_cache_line_size(void) 
{
    int size = b579_cpu_cache_line_size_os();
    return (size > 0) ? size : 64; /* fallback: 64 bytes */
}

/* ══════════════════════════════════════════
 *  Thread Pinning — validate then delegate
 * ══════════════════════════════════════════ */

b579_result_t b579_cpu_pin_thread(int core_id) {
    /* Guard: validate core_id */
    int max_cores = b579_cpu_count();

    if (core_id < 0 || core_id >= max_cores) 
    {
        b579_error_set(B579_ERR_RANGE,"core_id %d out of range [0, %d)",core_id, max_cores);
        return B579_ERR_RANGE;
    }
    b579_result_t r = b579_cpu_pin_thread_os(core_id);

    if (B579_IS_OK(r)) 
    {
        B579_DBG("Thread pinned to core %d", core_id);
    }
    return r;
}

b579_result_t b579_cpu_unpin_thread(void) 
{
    return b579_cpu_unpin_thread_os();
}

int b579_cpu_current_core(void) 
{
    return b579_cpu_current_core_os();
}

/* ══════════════════════════════════════════
 *  Priority — delegate
 * ══════════════════════════════════════════ 
 */

b579_result_t b579_cpu_set_high_priority(void) 
{
    b579_result_t r = b579_cpu_set_high_priority_os();
    if (B579_IS_OK(r)) 
    {
        B579_DBG("Process set to high priority");
    }
    return r;
}

b579_result_t b579_cpu_set_realtime_priority(void) 
{
    b579_result_t r = b579_cpu_set_realtime_priority_os();
    if (B579_IS_OK(r)) 
    {
        B579_DBG("Process set to realtime priority");
    }
    return r;
}


















