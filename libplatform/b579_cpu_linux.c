

#ifdef B579_OS_LINUX

#define _GNU_SOURCE /* Required for CPU_ZERO, CPU_SET, sched_getcpu */
#include <sched.h>
#include <unistd.h>
#include <sys/resource.h>

#include "include/b579_platform_internal.h"

/* ── CPU Count ── */

int b579_cpu_count_os(void) 
{
    long count = sysconf(_SC_NPROCESSORS_ONLN);
    return (count > 0) ? (int)count : 1;
}

/* ── Cache Line Size ── */

int b579_cpu_cache_line_size_os(void) 
{
    long size = sysconf(_SC_LEVEL1_DCACHE_LINESIZE);
    return (size > 0) ? (int)size : 64;
}

/* ── Pin Thread ── */

b579_result_t b579_cpu_pin_thread_os(int core_id) 
{
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(core_id, &cpuset);

    if (sched_setaffinity(0, sizeof(cpuset), &cpuset) != 0) 
    {
        b579_error_set_errno("sched_setaffinity");
        return B579_ERR_PERM;
    }
    return B579_OK;
}

/* ── Unpin Thread ── */

b579_result_t b579_cpu_unpin_thread_os(void) 
{
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    /* Allow ALL cores */
    int count = b579_cpu_count_os();

    for (int i = 0; i < count; i++) 
    {
        CPU_SET(i, &cpuset);
    }

    if (sched_setaffinity(0, sizeof(cpuset), &cpuset) != 0) 
    {
        b579_error_set_errno("sched_setaffinity (unpin)");
        return B579_ERR;
    }
    return B579_OK;
}

/* ── Current Core ── */

int b579_cpu_current_core_os(void) 
{
    return sched_getcpu(); /* returns -1 on error */
}

/* ── High Priority ── */

b579_result_t b579_cpu_set_high_priority_os(void) 
{
    /* Nice value: -20 = highest priority (needs root) */
    if (setpriority(PRIO_PROCESS, 0, -20) != 0) 
    {
        b579_error_set_errno("setpriority(-20)");
        return B579_ERR_PERM;
    }
    return B579_OK;
}

/* ── Realtime Priority ── */

b579_result_t b579_cpu_set_realtime_priority_os(void) 
{
    struct sched_param param;
    param.sched_priority = sched_get_priority_max(SCHED_FIFO);

    if (sched_setscheduler(0, SCHED_FIFO, &param) != 0) 
    {
        b579_error_set_errno("sched_setscheduler(SCHED_FIFO)");
        return B579_ERR_PERM;
    }
    return B579_OK;
}

#endif /* B579_OS_LINUX */

