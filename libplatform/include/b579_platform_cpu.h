#pragma once

#ifndef B579_PLATFORM_CPU_H
#define B579_PLATFORM_CPU_H

#include "b579_platform_types.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ══════════════════════════════════════════
 *  CPU Information
 * ══════════════════════════════════════════ 
 */

/* Get number of online (available) CPU cores */
int b579_cpu_count(void);

/* Get L1 cache line size in bytes (typically 64) */
/* Useful for padding structs to avoid false sharing */
int b579_cpu_cache_line_size(void);

/* ══════════════════════════════════════════
 *  Thread Pinning (CPU Affinity)
 * ══════════════════════════════════════════ 
 */

/* Pin current thread to specific CPU core */
/* core_id: 0-based, must be < b579_cpu_count() */
b579_result_t b579_cpu_pin_thread(int core_id);

/* Unpin current thread (allow OS to schedule freely) */
b579_result_t b579_cpu_unpin_thread(void);

/* Get which core the current thread is running on */
/* Returns core_id or -1 on error */
int b579_cpu_current_core(void);

/* ══════════════════════════════════════════
 *  Process Priority
 * ══════════════════════════════════════════ 
 */

/* Set current process to high priority (needs root/admin) */
b579_result_t b579_cpu_set_high_priority(void);

/* Set current process to realtime priority (dangerous, needs root) */
b579_result_t b579_cpu_set_realtime_priority(void);

#ifdef __cplusplus
}
#endif

#endif /* B579_PLATFORM_CPU_H */















































