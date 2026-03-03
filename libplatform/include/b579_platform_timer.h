#pragma once


#ifndef B579_PLATFORM_TIMER_H
#define B579_PLATFORM_TIMER_H

#include "b579_platform_types.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ══════════════════════════════════════════
 *  Timer API
 * ══════════════════════════════════════════ 
 */

/* Initialize timer subsystem (calibration on some platforms) */
b579_result_t b579_timer_init(void);

/* Get current time in nanoseconds (monotonic clock) */
/* Monotonic = never goes backwards, unaffected by NTP adjustments */
uint64_t b579_timer_nanos(void);

/* Get current time in microseconds */
uint64_t b579_timer_micros(void);

/* Get current time in milliseconds */
uint64_t b579_timer_millis(void);

/* Get current time in seconds (floating point) */
double b579_timer_secs(void);

/* ══════════════════════════════════════════
 *  Sleep / Wait API
 * ══════════════════════════════════════════ 
 */

/* Sleep for at least `ns` nanoseconds (OS-level, may overshoot) */
void b579_timer_sleep_ns(uint64_t ns);

/* Sleep for at least `ms` milliseconds */
void b579_timer_sleep_ms(uint64_t ms);

/* Busy-wait for exactly `ns` nanoseconds (spin loop) */
/* WARNING: burns CPU! Use only for < 1ms precision delays */
void b579_timer_busywait_ns(uint64_t ns);

/* ══════════════════════════════════════════
 *  Stopwatch — measure elapsed time
 *
 *  Pattern: RAII — start/stop pairs
 *
 *  Usage:
 *    b579_stopwatch_t sw;
 *    b579_stopwatch_start(&sw);
 *    // ... work ...
 *    uint64_t elapsed_ns = b579_stopwatch_elapsed_ns(&sw);
 * ══════════════════════════════════════════ 
 */

typedef struct {
    uint64_t start_ns;
} b579_stopwatch_t;

/* Start measuring */
void b579_stopwatch_start(b579_stopwatch_t *sw);

/* Get elapsed time without stopping */
uint64_t b579_stopwatch_elapsed_ns(const b579_stopwatch_t *sw);
uint64_t b579_stopwatch_elapsed_us(const b579_stopwatch_t *sw);
uint64_t b579_stopwatch_elapsed_ms(const b579_stopwatch_t *sw);
double   b579_stopwatch_elapsed_secs(const b579_stopwatch_t *sw);

#ifdef __cplusplus
}
#endif

#endif /* B579_PLATFORM_TIMER_H */














































