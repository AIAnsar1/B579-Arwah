#pragma once

#ifndef B579_PLATFORM_DETECT_H
#define B579_PLATFORM_DETECT_H

/*
 * B-579 Arwah — Platform Detection
 *
 * Compile-time detection of:
 *   - Operating system (Linux, macOS, Windows, FreeBSD)
 *   - CPU architecture (x86_64, ARM64, x86)
 *   - Compiler (GCC, Clang, MSVC)
 *   - C standard version
 *
 * Design: Header-only, zero cost at runtime.
 *         All decisions made by preprocessor.
 *
 * Pattern: DRY — detect once, use everywhere.
 *          Every other file includes this instead of
 *          writing its own #ifdef chains.
 * ══════════════════════════════════════════
 *  Operating System Detection
 *
 *  After this block, exactly ONE of these is defined:
 *    B579_OS_LINUX
 *    B579_OS_MACOS
 *    B579_OS_FREEBSD
 *    B579_OS_WINDOWS
 *    B579_OS_UNKNOWN
 *
 *  Plus convenience groups:
 *    B579_OS_UNIX    — any POSIX-like (Linux, macOS, FreeBSD)
 *    B579_OS_APPLE   — macOS / iOS
 *    B579_OS_BSD     — FreeBSD, macOS (BSD-derived)
 * ══════════════════════════════════════════ 
 */


#if defined(__linux__) || defined(__linux) || defined(linux)
    #define B579_OS_LINUX 1
    #define B579_OS_UNIX 1
    #define B579_OS_NAME "Linux"
#elif defined(__APPLE__) && defined(__MACH__)
    #define B579_OS_MACOS   1
    #define B579_OS_APPLE   1
    #define B579_OS_BSD     1
    #define B579_OS_UNIX    1
    #define B579_OS_NAME    "macOS"
#elif defined(__FreeBSD__)
    #define B579_OS_FREEBSD 1
    #define B579_OS_BSD     1
    #define B579_OS_UNIX    1
    #define B579_OS_NAME    "FreeBSD"
#elif defined(_WIN32) || defined(_WIN64) || defined(__CYGWIN__)
    #define B579_OS_WINDOWS 1
    #define B579_OS_NAME    "Windows"
#else
    #define B579_OS_UNKNOWN 1
    #define B579_OS_NAME    "Unknown"
    #warning "B579: Unknown operating system. Some features may not work."
#endif

/* ══════════════════════════════════════════
 *  CPU Architecture Detection
 *
 *  After this block, exactly ONE of these is defined:
 *    B579_ARCH_X86_64
 *    B579_ARCH_X86
 *    B579_ARCH_ARM64
 *    B579_ARCH_ARM
 *    B579_ARCH_UNKNOWN
 *
 *  Plus convenience:
 *    B579_ARCH_64BIT  — 64-bit architecture
 *    B579_ARCH_BITS   — 32 or 64
 * ══════════════════════════════════════════ 
 */
 #if defined(__x86_64__) || defined(_M_X64) || defined(__amd64__)
    #define B579_ARCH_X86_64  1
    #define B579_ARCH_64BIT   1
    #define B579_ARCH_BITS    64
    #define B579_ARCH_NAME    "x86_64"
#elif defined(__i386__) || defined(_M_IX86) || defined(__i686__)
    #define B579_ARCH_X86     1
    #define B579_ARCH_BITS    32
    #define B579_ARCH_NAME    "x86"
#elif defined(__aarch64__) || defined(_M_ARM64)
    #define B579_ARCH_ARM64   1
    #define B579_ARCH_64BIT   1
    #define B579_ARCH_BITS    64
    #define B579_ARCH_NAME    "ARM64"
#elif defined(__arm__) || defined(_M_ARM)
    #define B579_ARCH_ARM     1
    #define B579_ARCH_BITS    32
    #define B579_ARCH_NAME    "ARM"
#else
    #define B579_ARCH_UNKNOWN 1
    #define B579_ARCH_BITS    64 /* assume 64-bit */
    #define B579_ARCH_NAME    "Unknown"
#endif

/* ══════════════════════════════════════════
 *  Compiler Detection
 *
 *  B579_COMPILER_GCC
 *  B579_COMPILER_CLANG
 *  B579_COMPILER_MSVC
 *  B579_COMPILER_UNKNOWN
 *
 *  B579_COMPILER_VERSION  — numeric version for comparisons
 * ══════════════════════════════════════════ 
 */

 #if defined(__clang__)
 /* Clang MUST be checked before GCC — clang also defines __GNUC__ */
    #define B579_COMPILER_CLANG    1
    #define B579_COMPILER_NAME     "Clang"
    #define B579_COMPILER_VERSION  (__clang_major__ * 10000 + __clang_minor__ * 100 + __clang_patchlevel__)
#elif defined(__GNUC__)
    #define B579_COMPILER_GCC      1
    #define B579_COMPILER_NAME     "GCC"
    #define B579_COMPILER_VERSION  (__GNUC__ * 10000 + __GNUC_MINOR__ * 100 +  __GNUC_PATCHLEVEL__)
#elif defined(_MSC_VER)
    #define B579_COMPILER_MSVC     1
    #define B579_COMPILER_NAME     "MSVC"
    #define B579_COMPILER_VERSION  _MSC_VER
#else
    #define B579_COMPILER_UNKNOWN  1
    #define B579_COMPILER_NAME     "Unknown"
    #define B579_COMPILER_VERSION  0
#endif

/* ══════════════════════════════════════════
 *  Compiler Attributes / Hints
 *
 *  Portable wrappers for compiler-specific attributes.
 *  On unsupported compilers, these expand to nothing.
 * ══════════════════════════════════════════ 
 */

/* Function never returns (exit, abort) */

#if defined(B579_COMPILER_GCC) || defined(B579_COMPILER_CLANG)
    #define B579_NORETURN       __attribute__((noreturn))
#elif defined(B579_COMPILER_MSVC)
    #define B579_NORETURN       __declspec(noreturn)
#else
    #define B579_NORETURN
#endif

/* Function result must be checked */
#if defined(B579_COMPILER_GCC) || defined(B579_COMPILER_CLANG)
    #define B579_WARN_UNUSED    __attribute__((warn_unused_result))
#else
    #define B579_WARN_UNUSED
#endif

/* Likely/unlikely branch hints for branch predictor */
#if defined(B579_COMPILER_GCC) || defined(B579_COMPILER_CLANG)
    #define B579_LIKELY(x)      __builtin_expect(!!(x), 1)
    #define B579_UNLIKELY(x)    __builtin_expect(!!(x), 0)
#else
    #define B579_LIKELY(x)      (x)
    #define B579_UNLIKELY(x)    (x)
#endif

/* Force inline */
#if defined(B579_COMPILER_GCC) || defined(B579_COMPILER_CLANG)
    #define B579_INLINE         static inline __attribute__((always_inline))
#elif defined(B579_COMPILER_MSVC)
    #define B579_INLINE         static __forceinline
#else
    #define B579_INLINE         static inline
#endif

/* Unused parameter — suppress warnings without removing the name */
#define B579_UNUSED(x)          ((void)(x))

/* CPU pause hint — used in spin loops */
#if defined(B579_ARCH_X86_64) || defined(B579_ARCH_X86)
    #if defined(B579_COMPILER_GCC) || defined(B579_COMPILER_CLANG)
        #define B579_CPU_PAUSE()  __builtin_ia32_pause()
    #elif defined(B579_COMPILER_MSVC)
        #include <intrin.h>
        #define B579_CPU_PAUSE()  _mm_pause()
    #else
        #define B579_CPU_PAUSE()  ((void)0)
    #endif
#elif defined(B579_ARCH_ARM64)
    #define B579_CPU_PAUSE()      __asm__ volatile("yield")
#else
    #define B579_CPU_PAUSE()      ((void)0)
#endif

/* ══════════════════════════════════════════
 *  Feature Detection
 *
 *  B579_HAS_SIMD_AVX2    — AVX2 intrinsics available at compile time
 *  B579_HAS_SIMD_SSE4    — SSE4.1 available
 *  B579_HAS_PTHREADS     — POSIX threads available
 *  B579_HAS_C11_ATOMICS  — C11 <stdatomic.h> available
 * ══════════════════════════════════════════ 
 */


#ifdef B579_OS_UNIX
    #define B579_HAS_PTHREADS   1
#endif

/* C11 atomics */
#if defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L
 #if !defined(__STDC_NO_ATOMICS__)
     #define B579_HAS_C11_ATOMICS  1
 #endif
#endif
/* SIMD — compile-time check (runtime check still needed!) */
#if defined(__AVX2__)
    #define B579_HAS_SIMD_AVX2  1
#endif

#if defined(__SSE4_1__)
    #define B579_HAS_SIMD_SSE4  1
#endif




#endif /* B579_PLATFORM_DETECT_H */

