



#ifdef B579_OS_WINDOWS

#include "include/b579_platform_internal.h"

/* Must define WIN32_LEAN_AND_MEAN before windows.h */
#ifndef WIN32_LEAN_AND_MEAN
    #define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

/* QPC frequency: ticks per second */
static double ticks_to_nanos = 0.0;

/* ── Init ── */

b579_result_t b579_timer_init_os(void) 
{
    LARGE_INTEGER freq;

    if (!QueryPerformanceFrequency(&freq) || freq.QuadPart == 0) 
    {
        b579_error_set_win32("QueryPerformanceFrequency");
        return B579_ERR;
    }

    /* nanos = ticks * (1,000,000,000 / frequency) */
    ticks_to_nanos = 1000000000.0 / (double)freq.QuadPart;
    B579_DBG("Windows timer: frequency=%lld factor=%.6f",freq.QuadPart, ticks_to_nanos);
    return B579_OK;
}

/* ── Nanosecond Time ── */

uint64_t b579_timer_nanos_os(void) 
{
    LARGE_INTEGER now;
    QueryPerformanceCounter(&now);
    return (uint64_t)((double)now.QuadPart * ticks_to_nanos);
}

/* ── Sleep ── */

void b579_timer_sleep_ns_os(uint64_t ns) 
{
    /* Windows Sleep has 1ms minimum granularity */
    /* For sub-millisecond: we use busy-wait from timer.c */
    DWORD ms = (DWORD)(ns / 1000000ULL);
    if (ms > 0) 
    {
        Sleep(ms);
    }
    /* Remaining sub-ms portion handled by busywait in timer.c */
}

#endif /* B579_OS_WINDOWS */



