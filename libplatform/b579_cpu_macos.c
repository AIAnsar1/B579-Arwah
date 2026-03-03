

#ifdef B579_OS_MACOS

#include <sys/sysctl.h>
#include <sys/resource.h>
#include <pthread.h>
#include <mach/mach.h>
#include <mach/thread_policy.h>
#include <mach/thread_act.h>

#include "include/b579_platform_internal.h"

/* ── CPU Count ── */

int b579_cpu_count_os(void) 
{
    int count = 0;
    size_t len = sizeof(count);

    if (sysctlbyname("hw.ncpu", &count, &len, NULL, 0) != 0) 
    {
        return 1;
    }
    return count;
}

/* ── Cache Line Size ── */

int b579_cpu_cache_line_size_os(void) 
{
    int size = 0;
    size_t len = sizeof(size);

    if (sysctlbyname("hw.cachelinesize", &size, &len, NULL, 0) != 0) 
    {
        return 64;
    }
    return size;
}

/* ── Pin Thread (affinity hint) ── */

b579_result_t b579_cpu_pin_thread_os(int core_id) 
{
    thread_affinity_policy_data_t policy;
    policy.affinity_tag = core_id + 1; /* 0 means no affinity */
    kern_return_t kr = thread_policy_set(pthread_mach_thread_np(pthread_self()),THREAD_AFFINITY_POLICY,(thread_policy_t)&policy,THREAD_AFFINITY_POLICY_COUNT);

    if (kr != KERN_SUCCESS) 
    {
        b579_error_set(B579_ERR, "thread_policy_set failed: %d", kr);
        return B579_ERR;
    }
    return B579_OK;
}

/* ── Unpin Thread ── */

b579_result_t b579_cpu_unpin_thread_os(void) 
{
    thread_affinity_policy_data_t policy;
    policy.affinity_tag = 0; /* 0 = no affinity */
    kern_return_t kr = thread_policy_set(pthread_mach_thread_np(pthread_self()),THREAD_AFFINITY_POLICY,(thread_policy_t)&policy,THREAD_AFFINITY_POLICY_COUNT);
    return (kr == KERN_SUCCESS) ? B579_OK : B579_ERR;
}

/* ── Current Core ── */

int b579_cpu_current_core_os(void) 
{
    /* macOS doesn't have sched_getcpu() */
    /* Best effort: not available, return -1 */
    return -1;
}

/* ── High Priority ── */

b579_result_t b579_cpu_set_high_priority_os(void) 
{
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
    /* macOS doesn't support SCHED_FIFO for regular processes */
    /* Use thread QOS instead */
    if (pthread_set_qos_class_self_np(QOS_CLASS_USER_INTERACTIVE, 0) != 0) 
    {
        b579_error_set_errno("pthread_set_qos_class_self_np");
        return B579_ERR_PERM;
    }
    return B579_OK;
}

#endif /* B579_OS_MACOS */

