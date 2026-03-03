#pragma once

#ifndef B579_PLATFORM_ENDIAN_H
#define B579_PLATFORM_ENDIAN_H

#include <stdint.h>
#include <string.h> /* memcpy */

#include "b579_platform_detect.h"

/*
 * B-579 Arwah — Byte Order Utilities
 *
 * Network protocols use big-endian (network byte order).
 * Most modern CPUs use little-endian.
 * These macros handle conversion portably.
 *
 * Pattern: KISS — simple macros, zero overhead.
 */

/* ══════════════════════════════════════════
 *  Detect Byte Order
 * ══════════════════════════════════════════ 
 */

#if defined(__BYTE_ORDER__)
    #if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
        #define B579_LITTLE_ENDIAN  1
    #elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
        #define B579_BIG_ENDIAN     1
    #endif
#elif defined(B579_OS_WINDOWS)
    /* Windows is always little-endian on supported architectures */
    #define B579_LITTLE_ENDIAN  1
#elif defined(B579_ARCH_X86_64) || defined(B579_ARCH_X86)
    /* x86 is always little-endian */
    #define B579_LITTLE_ENDIAN  1
#else
    /* Safe default */
    #define B579_LITTLE_ENDIAN  1
#endif


/* ══════════════════════════════════════════
 *  Byte Swap Primitives
 *
 *  Use compiler builtins when available (single instruction).
 *  Fall back to manual bit manipulation.
 * ══════════════════════════════════════════ 
 */
#if defined(B579_COMPILER_GCC) || defined(B579_COMPILER_CLANG)
    #define b579_bswap16(x) __builtin_bswap16(x)
    #define b579_bswap32(x) __builtin_bswap32(x)
    #define b579_bswap64(x) __builtin_bswap64(x)
#elif defined(B579_COMPILER_MSVC)
    #include <stdlib.h>

    #define b579_bswap16(x) _byteswap_ushort(x)
    #define b579_bswap32(x) _byteswap_ulong(x)
    #define b579_bswap64(x) _byteswap_uint64(x)

#else
     /* Manual fallback */
     B579_INLINE uint16_t b579_bswap16(uint16_t x)
     {
        return (x >> 8) | (x << 8);
     }

     B579_INLINE uint32_t b579_bswap32(uint32_t x) 
     {
        return ((x >> 24) & 0x000000FF) |
               ((x >>  8) & 0x0000FF00) |
               ((x <<  8) & 0x00FF0000) |
               ((x << 24) & 0xFF000000);
    }

    B579_INLINE uint64_t b579_bswap64(uint64_t x) 
    {
        return ((x >> 56) & 0x00000000000000FFULL) |
               ((x >> 40) & 0x000000000000FF00ULL) |
               ((x >> 24) & 0x0000000000FF0000ULL) |
               ((x >>  8) & 0x00000000FF000000ULL) |
               ((x <<  8) & 0x000000FF00000000ULL) |
               ((x << 24) & 0x0000FF0000000000ULL) |
               ((x << 40) & 0x00FF000000000000ULL) |
               ((x << 56) & 0xFF00000000000000ULL);
    }

#endif


/* ══════════════════════════════════════════
 *  Host ↔ Network Byte Order
 *
 *  Network byte order = Big Endian (RFC 1700)
 *
 *  b579_hton16 = host to network (16-bit)
 *  b579_ntoh16 = network to host (16-bit)
 *  etc.
 * ══════════════════════════════════════════ 
 */

#if defined(B579_LITTLE_ENDIAN)
    /* Little-endian: need to swap */
    #define b579_hton16(x)  b579_bswap16(x)
    #define b579_hton32(x)  b579_bswap32(x)
    #define b579_hton64(x)  b579_bswap64(x)
    #define b579_ntoh16(x)  b579_bswap16(x)
    #define b579_ntoh32(x)  b579_bswap32(x)
    #define b579_ntoh64(x)  b579_bswap64(x)
#else
    /* Big-endian: already in network order, no-op */
    #define b579_hton16(x)  (x)
    #define b579_hton32(x)  (x)
    #define b579_hton64(x)  (x)
    #define b579_ntoh16(x)  (x)
    #define b579_ntoh32(x)  (x)
    #define b579_ntoh64(x)  (x)
#endif

/* ══════════════════════════════════════════
 *  Unaligned Read/Write
 *
 *  Safe reading from arbitrary memory positions.
 *  Network packets are NOT aligned — never cast
 *  a byte pointer to uint32_t* directly!
 * ══════════════════════════════════════════ 
 */


B579_INLINE uint16_t b579_read_u16(const void *ptr) 
{
    uint16_t val;
    memcpy(&val, ptr, sizeof(val));
    return val;
}

B579_INLINE uint32_t b579_read_u32(const void *ptr) 
{
    uint32_t val;
    memcpy(&val, ptr, sizeof(val));
    return val;
}

B579_INLINE uint64_t b579_read_u64(const void *ptr) 
{
    uint64_t val;
    memcpy(&val, ptr, sizeof(val));
    return val;
}

B579_INLINE void b579_write_u16(void *ptr, uint16_t val) 
{
    memcpy(ptr, &val, sizeof(val));
}

B579_INLINE void b579_write_u32(void *ptr, uint32_t val) 
{
    memcpy(ptr, &val, sizeof(val));
}

B579_INLINE void b579_write_u64(void *ptr, uint64_t val) 
{
    memcpy(ptr, &val, sizeof(val));
}

/* Read as big-endian (network byte order) and convert to host */
B579_INLINE uint16_t b579_read_be16(const void *ptr) 
{
    return b579_ntoh16(b579_read_u16(ptr));
}

B579_INLINE uint32_t b579_read_be32(const void *ptr) 
{
    return b579_ntoh32(b579_read_u32(ptr));
}

/* Write host value as big-endian (network byte order) */
B579_INLINE void b579_write_be16(void *ptr, uint16_t val) 
{
    b579_write_u16(ptr, b579_hton16(val));
}

B579_INLINE void b579_write_be32(void *ptr, uint32_t val) 
{
    b579_write_u32(ptr, b579_hton32(val));
}






























#endif /* B579_PLATFORM_ENDIAN_H */
