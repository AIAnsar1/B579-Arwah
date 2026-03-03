

#include "include/b579_platform_internal.h"
#include "include/b579_platform_types.h"

/*
 * B-579 Arwah — Timer Dispatcher
 *
 * This file provides the PUBLIC timer API.
 * It delegates to OS-specific implementations
 * via functions declared in platform_internal.h.
 *
 * Pattern: Strategy (compile-time dispatch)
 *          The right timer_*.c is compiled based on
 *          target OS. This file just delegates.
 *
 * Principle: OCP (Open/Closed)
 *            To add a new OS: create timer_newos.c,
 *            implement b579_timer_*_os functions.
 *            This file needs NO changes.
 */

/* ══════════════════════════════════════════
 *  Initialization
 * ══════════════════════════════════════════ 
 */

static bool timer_initialized = false;

b579_result_t b579_timer_init(void)
{
    if (timer_initialized)
    {
        return B579_OK;
    }
    b579_result_t r = b579_timer_init_os();

    if (B579_IS_OK(r)) 
    {
        timer_initialized = true;
        B579_DBG("timer initialized");
    }
    return r;
}

/* ══════════════════════════════════════════
 *  Time Queries — delegate to OS
 * ══════════════════════════════════════════ 
 */


uint64_t b579_timer_nanos(void) 
{
    return b579_timer_nanos_os();
}

uint64_t b579_timer_micros(void) 
{
    return b579_timer_nanos_os() / 1000ULL;
}

uint64_t b579_timer_millis(void) 
{
    return b579_timer_nanos_os() / 1000000ULL;
}

double b579_timer_secs(void) 
{
    return (double)b579_timer_nanos_os() / 1000000000.0;
}

/* ══════════════════════════════════════════
 *  Sleep — delegate to OS
 * ══════════════════════════════════════════ 
 */

void b579_timer_sleep_ns(uint64_t ns) 
{
    b579_timer_sleep_ns_os(ns);
}

void b579_timer_sleep_ms(uint64_t ms) 
{
    b579_timer_sleep_ns_os(ms * 1000000ULL);
}

/* ══════════════════════════════════════════
 *  Busy-Wait — platform-independent
 *
 *  Spins in a tight loop checking the timer.
 *  Uses B579_CPU_PAUSE() to hint the CPU.
 *  Accurate to ~10-50ns on modern hardware.
 * ══════════════════════════════════════════ 
 */

void b579_timer_busywait_ns(uint64_t ns) 
{
    uint64_t target = b579_timer_nanos() + ns;

    while (b579_timer_nanos() < target) 
    {
        B579_CPU_PAUSE();
    }
}

/* ══════════════════════════════════════════
 *  Stopwatch — uses timer internally
 * ══════════════════════════════════════════ 
 */

void b579_stopwatch_start(b579_stopwatch_t *sw)
{
    if (sw) 
    {
        sw->start_ns = b579_timer_nanos();
    }
}

uint64_t b579_stopwatch_elapsed_ns(const b579_stopwatch_t *sw) 
{
    if (!sw)
    {
        return 0;
    }
    return b579_timer_nanos() - sw->start_ns;
}

uint64_t b579_stopwatch_elapsed_us(const b579_stopwatch_t *sw) 
{
    return b579_stopwatch_elapsed_ns(sw) / 1000ULL;
}

uint64_t b579_stopwatch_elapsed_ms(const b579_stopwatch_t *sw) 
{
    return b579_stopwatch_elapsed_ns(sw) / 1000000ULL;
}

double b579_stopwatch_elapsed_secs(const b579_stopwatch_t *sw) 
{
    return (double)b579_stopwatch_elapsed_ns(sw) / 1000000000.0;
}




