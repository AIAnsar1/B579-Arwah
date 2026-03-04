#include "include/b579_packet_internal.h"

/* Runtime SIMD flags — set by b579_checksum_init() */
int b579_has_avx2 = 0;
int b579_has_sse4 = 0;

/* ══════════════════════════════════════════
 *  SIMD Detection
 * ══════════════════════════════════════════ */

#if defined(B579_ARCH_X86_64) || defined(B579_ARCH_X86)
#if defined(B579_COMPILER_GCC) || defined(B579_COMPILER_CLANG)
#include <cpuid.h>

static void detect_simd(void) 
{
    unsigned eax, ebx, ecx, edx;

    /* Check for SSE4.1 */
    if (__get_cpuid(1, &eax, &ebx, &ecx, &edx)) 
    {
        b579_has_sse4 = (ecx & bit_SSE4_1) != 0;
    }

    /* Check for AVX2 */
    if (__get_cpuid_count(7, 0, &eax, &ebx, &ecx, &edx)) 
    {
        b579_has_avx2 = (ebx & bit_AVX2) != 0;
    }
    B579_DBG("SIMD: AVX2=%d SSE4=%d", b579_has_avx2, b579_has_sse4);
}

#elif defined(B579_COMPILER_MSVC)
#include <intrin.h>

static void detect_simd(void) 
{
    int info[4];
    __cpuid(info, 1);
    b579_has_sse4 = (info[2] & (1 << 19)) != 0;

    __cpuidex(info, 7, 0);
    b579_has_avx2 = (info[1] & (1 << 5)) != 0;
}

#else
static void detect_simd(void) 
{
    b579_has_avx2 = 0;
    b579_has_sse4 = 0;
}
#endif
#else
/* Non-x86: no SIMD checksums */
static void detect_simd(void) 
{
    b579_has_avx2 = 0;
    b579_has_sse4 = 0;
}
#endif

b579_result_t b579_checksum_init(void) 
{
    detect_simd();
    return B579_OK;
}

/* ══════════════════════════════════════════
 *  Scalar Checksum — RFC 1071
 *
 *  Simple, portable, correct.
 *  Used as fallback on non-SIMD platforms.
 * ══════════════════════════════════════════ */

static uint16_t checksum_scalar(const void *data, size_t len) 
{
    const uint16_t *ptr = (const uint16_t *)data;
    uint32_t sum = 0;

    /* Sum all 16-bit words */
    while (len > 1) 
    {
        sum += *ptr++;
        len -= 2;
    }

    /* Handle odd trailing byte */
    if (len == 1) 
    {
        sum += *(const uint8_t *)ptr;
    }

    /* Fold 32-bit sum into 16 bits */
    while (sum >> 16) 
    {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    return (uint16_t)(~sum);
}

/* ══════════════════════════════════════════
 *  Public: Auto-dispatching checksum
 * ══════════════════════════════════════════ */

uint16_t b579_checksum(const void *data, size_t len) 
{
    if (!data || len == 0)
    {
        return 0;
    }

    /*
     * For small packets (< 64 bytes), scalar is faster
     * because SIMD has setup overhead.
     * Most TCP/IP headers are 20-60 bytes.
     */
    if (B579_LIKELY(len < 64 || !b579_has_avx2)) 
    {
        return checksum_scalar(data, len);
    }
    /* Large data: use SIMD */
    return b579_checksum_simd(data, len);
}

/* ══════════════════════════════════════════
 *  Pseudo-Header Checksums
 *
 *  TCP and UDP checksums include a "pseudo-header"
 *  from the IP layer: src_ip, dst_ip, protocol, length.
 *  This prevents packets from being routed to wrong hosts.
 * ══════════════════════════════════════════ */

uint16_t b579_checksum_tcp(uint32_t src_ip,uint32_t dst_ip,const void *tcp_hdr,size_t tcp_len) {
    uint32_t sum = 0;
    /* Pseudo-header fields in network byte order */
    uint32_t src_n = b579_hton32(src_ip);
    uint32_t dst_n = b579_hton32(dst_ip);
    sum += (src_n >> 16) & 0xFFFF;
    sum += (src_n      ) & 0xFFFF;
    sum += (dst_n >> 16) & 0xFFFF;
    sum += (dst_n      ) & 0xFFFF;
    sum += b579_hton16(B579_IPPROTO_TCP);
    sum += b579_hton16((uint16_t)tcp_len);
    /* Add TCP segment */
    const uint16_t *ptr = (const uint16_t *)tcp_hdr;
    size_t remaining = tcp_len;

    while (remaining > 1) 
    {
        sum += *ptr++;
        remaining -= 2;
    }

    if (remaining == 1)
    {
        sum += *(const uint8_t *)ptr;
    }

    /* Fold */
    while (sum >> 16) 
    {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    return (uint16_t)(~sum);
}

uint16_t b579_checksum_udp(uint32_t src_ip,uint32_t dst_ip,const void *udp_hdr,size_t udp_len) 
{
    uint32_t sum = 0;
    uint32_t src_n = b579_hton32(src_ip);
    uint32_t dst_n = b579_hton32(dst_ip);
    sum += (src_n >> 16) & 0xFFFF;
    sum += (src_n      ) & 0xFFFF;
    sum += (dst_n >> 16) & 0xFFFF;
    sum += (dst_n      ) & 0xFFFF;
    sum += b579_hton16(B579_IPPROTO_UDP);
    sum += b579_hton16((uint16_t)udp_len);
    const uint16_t *ptr = (const uint16_t *)udp_hdr;
    size_t remaining = udp_len;

    while (remaining > 1) 
    {
        sum += *ptr++;
        remaining -= 2;
    }

    if (remaining == 1) 
    {
        sum += *(const uint8_t *)ptr;
    }

    while (sum >> 16) 
    {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    uint16_t result = (uint16_t)(~sum);
    return result == 0 ? 0xFFFF : result;
}

uint16_t b579_checksum_icmp(const void *icmp_hdr, size_t len) 
{
    return checksum_scalar(icmp_hdr, len);
}


