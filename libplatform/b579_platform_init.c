#include <stdio.h>

#include "include/b579_platform_internal.h"


static bool platform_initialized = false;

/* Static buffer for platform info string */
static char platform_info_buf[256] = {0};

b579_result_t b579_platform_init(void) 
{
    if (platform_initialized) 
    {
        return B579_OK;
    }
    b579_result_t r;
    /* 1. Error subsystem first (others may use it) */
    r = b579_error_init();

    if (B579_IS_ERR(r))
    {
        return r;
    }
    /* 2. Timer */
    r = b579_timer_init();

    if (B579_IS_ERR(r))
    {
        return r;
    }
    /* 3. Build platform info string */
    snprintf(platform_info_buf, sizeof(platform_info_buf),"%s %s (%s %d)",B579_OS_NAME,B579_ARCH_NAME,B579_COMPILER_NAME,B579_COMPILER_VERSION);
    platform_initialized = true;
    B579_DBG("platform initialized: %s", platform_info_buf);
    return B579_OK;
}

void b579_platform_shutdown(void) 
{
    if (!platform_initialized)
    {
        return;
    }

    /* Print memory stats in debug builds */
#ifndef NDEBUG
    b579_mem_print_stats();
#endif

    b579_error_shutdown();
    platform_initialized = false;

    B579_DBG("platform shutdown complete");
}

const char *b579_platform_info(void) 
{
    return platform_info_buf;
}