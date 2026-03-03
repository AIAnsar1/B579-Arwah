

#ifdef B579_OS_LINUX
#include <time.h>

#include "include/b579_platform_internal.h"

/* ── Init ── */

b579_result_t b579_timer_init_os(void) 
{
    /* Verify CLOCK_MONOTONIC is available */
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) 
    {
        b579_error_set_errno("clock_gettime(CLOCK_MONOTONIC)");
        return B579_ERR;
    }
    return B579_OK;
}

/* ── Nanosecond Time ── */

uint64_t b579_timer_nanos_os(void) 
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

/* ── Sleep ── */

void b579_timer_sleep_ns_os(uint64_t ns) 
{
    struct timespec req;
    req.tv_sec  = (time_t)(ns / 1000000000ULL);
    req.tv_nsec = (long)(ns % 1000000000ULL);

    /* nanosleep can be interrupted by signals — retry */
    while (nanosleep(&req, &req) == -1 && errno == EINTR) 
    {
        /* interrupted, continue with remaining time */
    }
}

#endif /* B579_OS_LINUX */