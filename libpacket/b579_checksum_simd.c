#include "include/b579_packet_internal.h"

#if defined(B579_ARCH_X86_64) && (defined(B579_COMPILER_GCC) || defined(B579_COMPILER_CLANG))

#include <immintrin.h>

/*
 * AVX2 checksum — process 32 bytes at a time.
 * Accumulates 16-bit sums in 256-bit registers.
 */
uint16_t b579_checksum_simd(const void *data, size_t len) 
{
    if (!b579_has_avx2) 
    {
        return b579_checksum(data, len);
    }
    const uint8_t *ptr = (const uint8_t *)data;
    __m256i sum_vec = _mm256_setzero_si256();
    __m256i zero    = _mm256_setzero_si256();

    /* Process 32 bytes per iteration */
    while (len >= 32) 
    {
        __m256i chunk = _mm256_loadu_si256((const __m256i *)ptr);
        /* Unpack bytes to 16-bit words and accumulate */
        __m256i lo = _mm256_unpacklo_epi8(chunk, zero);
        __m256i hi = _mm256_unpackhi_epi8(chunk, zero);
        sum_vec = _mm256_add_epi32(sum_vec,_mm256_madd_epi16(lo, _mm256_set1_epi16(1)));
        sum_vec = _mm256_add_epi32(sum_vec,_mm256_madd_epi16(hi, _mm256_set1_epi16(1)));

        ptr += 32;
        len -= 32;
    }
    /* Horizontal sum: 256-bit → 128-bit → 64-bit → 32-bit */
    __m128i lo128 = _mm256_castsi256_si128(sum_vec);
    __m128i hi128 = _mm256_extracti128_si256(sum_vec, 1);
    __m128i sum128 = _mm_add_epi32(lo128, hi128);
    sum128 = _mm_add_epi32(sum128, _mm_srli_si128(sum128, 8));
    sum128 = _mm_add_epi32(sum128, _mm_srli_si128(sum128, 4));
    uint32_t sum = (uint32_t)_mm_extract_epi32(sum128, 0);
    /* Handle remaining bytes with scalar */
    const uint16_t *wptr = (const uint16_t *)ptr;

    while (len > 1) 
    {
        sum += *wptr++;
        len -= 2;
    }

    if (len == 1) 
    {
        sum += *(const uint8_t *)wptr;
    }

    /* Fold */
    while (sum >> 16) 
    {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    return (uint16_t)(~sum);
}

#else

/* Non-x86 or non-GCC/Clang: fall back to scalar */
uint16_t b579_checksum_simd(const void *data, size_t len) 
{
    return b579_checksum(data, len);
}

#endif