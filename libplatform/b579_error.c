#include <stdarg.h>
#include <stdio.h>

#include "include/b579_platform_internal.h"

/*
 * B-579 Arwah — Error Handling Implementation
 *
 * Thread-local error storage:
 *   Each thread gets its own error code + message buffer.
 *   No locks needed. No race conditions.
 *
 * Pattern: Thread-Local Singleton per thread
 * Principle: SRP — this file ONLY handles errors, nothing else
 */

/* ══════════════════════════════════════════
 *  Thread-Local Storage
 *
 *  Each thread has its own error state.
 *  __thread (GCC/Clang) or __declspec(thread) (MSVC).
 * ══════════════════════════════════════════ 
 */


typedef struct {
    b579_result_t code;
    char msg[B579_ERROR_MSG_MAX];
} b579_error_state_t;


#if defined(B579_COMPILER_GCC) || defined(B579_COMPILER_CLANG)
    static __thread b579_error_state_t tls_error = { B579_OK, "" };
#elif defined(B579_COMPILER_MSVC)
    static __declspec(thread) b579_error_state_t tls_error = { B579_OK, "" };
#else
    /* Fallback: single global (NOT thread-safe, but compiles) */
    static b579_error_state_t tls_error = { B579_OK, "" };
    #warning "B579: Thread-local storage not available. Error handling is NOT thread-safe."
#endif

/* ── Init / Shutdown ── */

b579_result_t b579_error_init(void) 
{
    b579_error_clear();
    return B579_OK;
}

void b579_error_shutdown(void) 
{
    b579_error_clear();
}

/* ── Set Error ── */

void b579_error_set(b579_result_t code, const char *fmt, ...) 
{
    tls_error.code = code;

    if (fmt) 
    {
        va_list args;
        va_start(args, fmt);
        vsnprintf(tls_error.msg, B579_ERROR_MSG_MAX, fmt, args);
        va_end(args);
    } else {
        tls_error.msg[0] = '\0';
    }
    B579_DBG("error set: code=%d msg='%s'", code, tls_error.msg);
}

/* ── Get Error ── */

b579_result_t b579_error_last_code(void) 
{
    return tls_error.code;
}

const char *b579_error_last_msg(void) 
{
    return tls_error.msg;
}

/* ── Clear ── */

void b579_error_clear(void) 
{
    tls_error.code = B579_OK;
    tls_error.msg[0] = '\0';
}

/* ── Error Code → String ── */

const char *b579_error_name(b579_result_t code) 
{
    switch (code) 
    {
        case B579_OK:          return "OK";
        case B579_ERR:         return "ERR_GENERIC";
        case B579_ERR_NULL:    return "ERR_NULL_POINTER";
        case B579_ERR_NOMEM:   return "ERR_OUT_OF_MEMORY";
        case B579_ERR_PERM:    return "ERR_PERMISSION_DENIED";
        case B579_ERR_NOSYS:   return "ERR_NOT_IMPLEMENTED";
        case B579_ERR_INVAL:   return "ERR_INVALID_ARGUMENT";
        case B579_ERR_RANGE:   return "ERR_OUT_OF_RANGE";
        case B579_ERR_TIMEOUT: return "ERR_TIMEOUT";
        case B579_ERR_BUSY:    return "ERR_RESOURCE_BUSY";
        case B579_ERR_IO:      return "ERR_IO";
        default:               return "ERR_UNKNOWN";
    }
}

/* ── Set from errno ── */

void b579_error_set_errno(const char *context) 
{
    int err = errno;
    b579_error_set(B579_ERR_IO, "%s: %s (errno=%d)",context ? context : "operation",strerror(err), err);
}

/* ── Set from Win32 GetLastError ── */

#ifdef B579_OS_WINDOWS
#include <windows.h>

void b579_error_set_win32(const char *context) 
{
    DWORD err = GetLastError();
    char buf[256];
    FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,NULL, err, 0, buf, sizeof(buf), NULL);
    b579_error_set(B579_ERR_IO, "%s: %s (win32=%lu)",context ? context : "operation", buf, err);
}
#endif























