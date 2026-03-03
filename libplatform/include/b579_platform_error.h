#pragma once

#ifndef B579_PLATFORM_ERROR_H
#define B579_PLATFORM_ERROR_H

#include "b579_platform_types.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Maximum length of error message string */
#define B579_ERROR_MSG_MAX  256

/* ══════════════════════════════════════════
 *  Error API
 * ══════════════════════════════════════════ */

/* Initialize error subsystem (call once at startup) */
b579_result_t b579_error_init(void);

/* Shutdown error subsystem */
void b579_error_shutdown(void);

/* Set last error for current thread */
void b579_error_set(b579_result_t code, const char *fmt, ...);

/* Get last error code for current thread */
b579_result_t b579_error_last_code(void);

/* Get last error message for current thread */
const char *b579_error_last_msg(void);

/* Clear last error for current thread */
void b579_error_clear(void);

/* Convert error code to string name */
const char *b579_error_name(b579_result_t code);

/* Set error from OS errno */
void b579_error_set_errno(const char *context);

#ifdef B579_OS_WINDOWS
/* Set error from GetLastError() */
void b579_error_set_win32(const char *context);
#endif

#ifdef __cplusplus
}
#endif









































#endif /* B579_PLATFORM_ERROR_H */

