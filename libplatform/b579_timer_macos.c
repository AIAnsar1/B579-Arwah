

#ifdef B579_OS_MACOS

#include <mach/mach_time.h>
#include <unistd.h>

#include "include/b579_platform_internal.h"

/* Conversion factor: ticks → nanoseconds */
static double ticks_to_nanos = 0.0;

/* ── Init ── */

b579_result_t b579_timer_init_os(void) 
{
    mach_timebase_info_data_t info;

    if (mach_timebase_info(&info) != KERN_SUCCESS) 
    {
        b579_error_set(B579_ERR, "mach_timebase_info failed");
        return B579_ERR;
    }

    /* nanos = ticks * numer / denom */
    ticks_to_nanos = (double)info.numer / (double)info.denom;
    B579_DBG("macOS timer: numer=%u denom=%u factor=%.6f",info.numer, info.denom, ticks_to_nanos);
    return B579_OK;
}

/* ── Nanosecond Time ── */

uint64_t b579_timer_nanos_os(void) 
{
    return (uint64_t)(mach_absolute_time() * ticks_to_nanos);
}

/* ── Sleep ── */

void b579_timer_sleep_ns_os(uint64_t ns) 
{
    /* macOS also supports nanosleep via POSIX */
    struct timespec req;
    req.tv_sec  = (time_t)(ns / 1000000000ULL);
    req.tv_nsec = (long)(ns % 1000000000ULL);

    while (nanosleep(&req, &req) == -1 && errno == EINTR) 
    {
        /* retry on signal interruption */
    }
}

#endif /* B579_OS_MACOS */

