#pragma once


#ifndef B579_PLATFORM_ATOMIC_H
#define B579_PLATFORM_ATOMIC_H

#include <stdint.h>

#include "b579_platform_detect.h"

/*
 * B-579 Arwah — Portable Atomic Operations
 *
 * Thread-safe counters without mutexes.
 * Used for packet statistics in the scan engine.
 *
 * Strategy:
 *   C11 stdatomic   → if available (preferred)
 *   GCC builtins    → fallback for older GCC/Clang
 *   Windows interlocked → MSVC
 *
 * Pattern: Strategy (compile-time dispatch)
 */
/* ══════════════════════════════════════════
 *  Implementation Selection
 * ══════════════════════════════════════════ 
 */

#if defined(B579_HAS_C11_ATOMICS)
    /* ── C11 Atomics (best option) ── */
    #include <stdatomic.h>

    typedef atomic_uint_fast64_t  b579_atomic_u64;
    typedef atomic_uint_fast32_t  b579_atomic_u32;
    typedef atomic_int_fast32_t   b579_atomic_i32;

    #define b579_atomic_init(ptr, val)       atomic_init(ptr, val)
    #define b579_atomic_load(ptr)            atomic_load_explicit(ptr, memory_order_relaxed)
    #define b579_atomic_store(ptr, val)      atomic_store_explicit(ptr, val, memory_order_relaxed)
    #define b579_atomic_add(ptr, val)        atomic_fetch_add_explicit(ptr, val, memory_order_relaxed)
    #define b579_atomic_sub(ptr, val)        atomic_fetch_sub_explicit(ptr, val, memory_order_relaxed)
    #define b579_atomic_or(ptr, val)         atomic_fetch_or_explicit(ptr, val, memory_order_relaxed)
    #define b579_atomic_cas(ptr, exp, des)   atomic_compare_exchange_weak_explicit(ptr, exp, des, memory_order_acq_rel, memory_order_relaxed)

#elif defined(B579_COMPILER_GCC) || defined(B579_COMPILER_CLANG)

    typedef volatile uint64_t  b579_atomic_u64;
    typedef volatile uint32_t  b579_atomic_u32;
    typedef volatile int32_t   b579_atomic_i32;

    #define b579_atomic_init(ptr, val)       (*(ptr) = (val))
    #define b579_atomic_load(ptr)            __atomic_load_n(ptr, __ATOMIC_RELAXED)
    #define b579_atomic_store(ptr, val)      __atomic_store_n(ptr, val, __ATOMIC_RELAXED)
    #define b579_atomic_add(ptr, val)        __atomic_fetch_add(ptr, val, __ATOMIC_RELAXED)
    #define b579_atomic_sub(ptr, val)        __atomic_fetch_sub(ptr, val, __ATOMIC_RELAXED)
    #define b579_atomic_or(ptr, val)         __atomic_fetch_or(ptr, val, __ATOMIC_RELAXED)
    #define b579_atomic_cas(ptr, exp, des)   __atomic_compare_exchange_n(ptr, exp, des, 1, __ATOMIC_ACQ_REL, __ATOMIC_RELAXED)

#elif defined(B579_COMPILER_MSVC)
    /* ── MSVC Interlocked ── */
    #include <intrin.h>

    typedef volatile long long  b579_atomic_u64;
    typedef volatile long       b579_atomic_u32;
    typedef volatile long       b579_atomic_i32;

    #define b579_atomic_init(ptr, val)       (*(ptr) = (val))
    #define b579_atomic_load(ptr)            (*(ptr))
    #define b579_atomic_store(ptr, val)      (*(ptr) = (val))
    #define b579_atomic_add(ptr, val)        InterlockedExchangeAdd64((volatile long long*)(ptr), (val))
    #define b579_atomic_sub(ptr, val)        InterlockedExchangeAdd64((volatile long long*)(ptr), -(long long)(val))
    #define b579_atomic_or(ptr, val)         InterlockedOr64((volatile long long*)(ptr), (val))

#else
    #error "B579: No atomic operations available for this compiler"
#endif


/* ══════════════════════════════════════════
 *  Convenience: Atomic Counter
 *
 *  Usage:
 *    b579_atomic_u64 packets_sent;
 *    b579_atomic_init(&packets_sent, 0);
 *    b579_atomic_add(&packets_sent, 1);
 *    uint64_t count = b579_atomic_load(&packets_sent);
 * ══════════════════════════════════════════ */

/* Increment by 1 */
#define b579_atomic_inc(ptr)    b579_atomic_add(ptr, 1)

/* Decrement by 1 */
#define b579_atomic_dec(ptr)    b579_atomic_sub(ptr, 1)










#endif /* B579_PLATFORM_ATOMIC_H */




