#pragma once


#ifndef B579_PLATFORM_INTERNAL_H
#define B579_PLATFORM_INTERNAL_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include "b579_platform.h"


/* ══════════════════════════════════════════
 *  Debug Logging (internal only)
 * ══════════════════════════════════════════ 
 */

#ifndef NDEBUG
    #define B579_DBG(fmt, ...) \
        fprintf(stderr, "[B579:%s:%d] " fmt "\n", \
                __FILE__, __LINE__, ##__VA_ARGS__)
#else
    #define B579_DBG(fmt, ...) ((void)0)
#endif

/* ══════════════════════════════════════════
 *  Forward Declarations: Timer backends
 *
 *  Each OS file implements these functions.
 *  timer.c dispatcher calls the right one via #ifdef.
 *
 *  Pattern: Strategy (compile-time selection)
 * ══════════════════════════════════════════ 
 */

b579_result_t b579_timer_init_os(void);
uint64_t b579_timer_nanos_os(void);
void b579_timer_sleep_ns_os(uint64_t ns);

/* ══════════════════════════════════════════
 *  Forward Declarations: CPU backends
 * ══════════════════════════════════════════ 
 */

int b579_cpu_count_os(void);
int b579_cpu_cache_line_size_os(void);
b579_result_t b579_cpu_pin_thread_os(int core_id);
b579_result_t b579_cpu_unpin_thread_os(void);
int b579_cpu_current_core_os(void);
b579_result_t b579_cpu_set_high_priority_os(void);
b579_result_t b579_cpu_set_realtime_priority_os(void);

/* ══════════════════════════════════════════
 *  Forward Declarations: Memory backends
 * ══════════════════════════════════════════ 
 */

b579_result_t b579_mem_lock_os(void *ptr, size_t size);
b579_result_t b579_mem_unlock_os(void *ptr, size_t size);
void *b579_mem_aligned_alloc_os(size_t size, size_t alignment);
void b579_mem_aligned_free_os(void *ptr);


#endif /* B579_PLATFORM_INTERNAL_H */














































