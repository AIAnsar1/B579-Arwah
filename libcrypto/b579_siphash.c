#include <string.h>

#include "include/b579_crypto_internal.h"


/* ══════════════════════════════════════════
 *  SipHash Round
 * ══════════════════════════════════════════ 
 */

#define SIPROUND                        \
    do {                                \
        v0 += v1; v1 = ROTL64(v1, 13); \
        v1 ^= v0; v0 = ROTL64(v0, 32); \
        v2 += v3; v3 = ROTL64(v3, 16); \
        v3 ^= v2;                       \
        v0 += v3; v3 = ROTL64(v3, 21); \
        v3 ^= v0;                       \
        v2 += v1; v1 = ROTL64(v1, 17); \
        v1 ^= v2; v2 = ROTL64(v2, 32); \
    } while (0)

/* ══════════════════════════════════════════
 *  Hash Arbitrary Data
 * ══════════════════════════════════════════ */

uint64_t b579_siphash(const void *data,size_t len,const b579_siphash_key_t *key) 
{
    if (!data || !key)
    {
        return 0;
    }
    uint64_t v0 = key->k0 ^ 0x736F6D6570736575ULL;
    uint64_t v1 = key->k1 ^ 0x646F72616E646F6DULL;
    uint64_t v2 = key->k0 ^ 0x6C7967656E657261ULL;
    uint64_t v3 = key->k1 ^ 0x7465646279746573ULL;
    const uint8_t *ptr = (const uint8_t *)data;
    const uint8_t *end = ptr + (len & ~7ULL);
    uint64_t b = ((uint64_t)len) << 56;

    /* Process 8-byte blocks */
    while (ptr < end) 
    {
        uint64_t m;
        memcpy(&m, ptr, 8);
        v3 ^= m;
        SIPROUND; /* Round 1 */
        SIPROUND; /* Round 2 */
        v0 ^= m;
        ptr += 8;
    }

    /* Process remaining bytes (0-7) */
    switch (len & 7) 
    {
        case 7: 
            b |= ((uint64_t)ptr[6]) << 48; /* FALLTHROUGH */
        case 6: 
            b |= ((uint64_t)ptr[5]) << 40; /* FALLTHROUGH */
        case 5: 
            b |= ((uint64_t)ptr[4]) << 32; /* FALLTHROUGH */
        case 4: 
            b |= ((uint64_t)ptr[3]) << 24; /* FALLTHROUGH */
        case 3: 
            b |= ((uint64_t)ptr[2]) << 16; /* FALLTHROUGH */
        case 2: 
            b |= ((uint64_t)ptr[1]) << 8;  /* FALLTHROUGH */
        case 1: 
            b |= ((uint64_t)ptr[0]); 
                break;
        case 0: 
            break;
    }
    v3 ^= b;
    SIPROUND;
    SIPROUND;
    v0 ^= b;
    /* Finalization: 4 rounds */
    v2 ^= 0xFF;
    SIPROUND;
    SIPROUND;
    SIPROUND;
    SIPROUND;
    return v0 ^ v1 ^ v2 ^ v3;
}

/* ══════════════════════════════════════════
 *  Hash IP:Port Pair (Optimized)
 *
 *  Most common use case in the scanner.
 *  Pack into 8 bytes and hash — avoids memory allocation.
 * ══════════════════════════════════════════ 
 */

uint64_t b579_siphash_ipport(uint32_t ip,uint16_t port,const b579_siphash_key_t *key) 
{
    uint64_t data = ((uint64_t)ip << 16) | port;
    return b579_siphash(&data, sizeof(data), key);
}

/* ══════════════════════════════════════════
 *  Hash Two uint64 Values
 * ══════════════════════════════════════════ 
 */

uint64_t b579_siphash_u64(uint64_t a,uint64_t b_val,const b579_siphash_key_t *key) 
{
    uint64_t data[2] = { a, b_val };
    return b579_siphash(data, sizeof(data), key);
}


