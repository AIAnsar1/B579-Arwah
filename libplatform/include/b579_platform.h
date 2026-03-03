#pragma once


#ifndef B579_PLATFORM_H
#define B579_PLATFORM_H

/* ── Detection (must be first) ── */
#include "b579_platform_detect.h"

/* ── Common Types ── */
#include "b579_platform_types.h"

/* ── Subsystems ── */
#include "b579_platform_error.h"
#include "b579_platform_timer.h"
#include "b579_platform_cpu.h"
#include "b579_platform_memory.h"
#include "b579_platform_endian.h"
#include "b579_platform_atomic.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ══════════════════════════════════════════
 *  Library Lifecycle
 *
 *  Pattern: RAII at library level.
 *  Call init once at startup, shutdown once at exit.
 * ══════════════════════════════════════════ 
 */

/* Initialize all platform subsystems */
b579_result_t b579_platform_init(void);

/* Shutdown all platform subsystems */
void b579_platform_shutdown(void);

/* Get platform description string */
/* Example: "Linux x86_64 (GCC 13.2.0)" */
const char *b579_platform_info(void);

/* Library version */
#define B579_PLATFORM_VERSION_MAJOR  0
#define B579_PLATFORM_VERSION_MINOR  1
#define B579_PLATFORM_VERSION_PATCH  0
#define B579_PLATFORM_VERSION_STRING "0.1.0"

#ifdef __cplusplus
}
#endif

#endif /* B579_PLATFORM_H */





