


#ifdef B579_OS_WINDOWS

#include "include/b579_platform_internal.h"

#ifndef WIN32_LEAN_AND_MEAN
    #define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

/* ── CPU Count ── */

int b579_cpu_count_os(void) 
{
    SYSTEM_INFO si;
    GetSystemInfo(&si);
    return (int)si.dwNumberOfProcessors;
}

/* ── Cache Line Size ── */

int b579_cpu_cache_line_size_os(void) 
{
    /* Windows: query via GetLogicalProcessorInformation */
    DWORD buf_size = 0;
    GetLogicalProcessorInformation(NULL, &buf_size);
    SYSTEM_LOGICAL_PROCESSOR_INFORMATION *buf = malloc(buf_size);

    if (!buf)
    {
        return 64;
    }
    int line_size = 64; /* default */

    if (GetLogicalProcessorInformation(buf, &buf_size)) 
    {
        DWORD count = buf_size / sizeof(SYSTEM_LOGICAL_PROCESSOR_INFORMATION);

        for (DWORD i = 0; i < count; i++) 
        {
            if (buf[i].Relationship == RelationCache && buf[i].Cache.Level == 1 && buf[i].Cache.Type == CacheData) 
            {
                line_size = (int)buf[i].Cache.LineSize;
                break;
            }
        }
    }
    free(buf);
    return line_size;
}

/* ── Pin Thread ── */

b579_result_t b579_cpu_pin_thread_os(int core_id) 
{
    DWORD_PTR mask = (DWORD_PTR)1 << core_id;

    if (SetThreadAffinityMask(GetCurrentThread(), mask) == 0) 
    {
        b579_error_set_win32("SetThreadAffinityMask");
        return B579_ERR;
    }
    return B579_OK;
}

/* ── Unpin Thread ── */

b579_result_t b579_cpu_unpin_thread_os(void) 
{
    /* Set affinity to all processors */
    SYSTEM_INFO si;
    GetSystemInfo(&si);
    DWORD_PTR mask = ((DWORD_PTR)1 << si.dwNumberOfProcessors) - 1;

    if (SetThreadAffinityMask(GetCurrentThread(), mask) == 0) 
    {
        b579_error_set_win32("SetThreadAffinityMask (unpin)");
        return B579_ERR;
    }
    return B579_OK;
}

/* ── Current Core ── */

int b579_cpu_current_core_os(void) 
{
    return (int)GetCurrentProcessorNumber();
}

/* ── High Priority ── */

b579_result_t b579_cpu_set_high_priority_os(void) 
{
    if (!SetPriorityClass(GetCurrentProcess(), HIGH_PRIORITY_CLASS)) 
    {
        b579_error_set_win32("SetPriorityClass(HIGH)");
        return B579_ERR_PERM;
    }
    return B579_OK;
}

/* ── Realtime Priority ── */

b579_result_t b579_cpu_set_realtime_priority_os(void) 
{
    if (!SetPriorityClass(GetCurrentProcess(), REALTIME_PRIORITY_CLASS)) 
    {
        b579_error_set_win32("SetPriorityClass(REALTIME)");
        return B579_ERR_PERM;
    }
    return B579_OK;
}

#endif /* B579_OS_WINDOWS */



