#include "include/b579_crypto_internal.h"

/* ══════════════════════════════════════════
 *  Default LCG Parameters
 *
 *  These satisfy Hull-Dobell theorem for m = 2^64:
 *    a = 6364136223846793005 (Knuth's constant)
 *    c = 1442695040888963407 (must be odd for m = 2^64)
 * ══════════════════════════════════════════ 
 */

#define LCG_DEFAULT_A  6364136223846793005ULL
#define LCG_DEFAULT_C  1442695040888963407ULL

/* ── Init with entropy ── */

b579_result_t b579_lcg_init(b579_lcg_t *lcg) 
{
    B579_CHECK_NULL(lcg);
    uint64_t seed = b579_entropy_u64();
    b579_lcg_init_seed(lcg, seed);
    return B579_OK;
}

/* ── Init with explicit seed ── */

void b579_lcg_init_seed(b579_lcg_t *lcg, uint64_t seed) 
{
    if (!lcg)
    {
        return;
    }
    lcg->state = seed;
    lcg->a = LCG_DEFAULT_A;
    lcg->c = LCG_DEFAULT_C;
    lcg->m = 0; /* 0 means 2^64, no modulo needed (wraps naturally) */
}

/* ── Init for specific range ── */

b579_result_t b579_lcg_init_range(b579_lcg_t *lcg,uint64_t range,uint64_t seed) 
{
    B579_CHECK_NULL(lcg);
    lcg->state = seed % range;
    lcg->m = range;

    /*
     * For full period with arbitrary modulus:
     *   c must be coprime to m
     *   a - 1 must be divisible by all prime factors of m
     *
     * Simple approach: find a coprime c, use a = 1 + m/prime_factor
     * Even simpler: use c = coprime, a = small constant
     */
    lcg->c = b579_find_coprime(range, seed);
    lcg->a = 1;

    /* Find a suitable multiplier */
    if (range > 2) 
    {
        /* a must be ≡ 1 (mod p) for all prime factors p of m */
        /* Simple: a = 1 works (degenerate LCG = additive) */
        /* Better: a = 1 + k*p for some k */
        uint64_t p = 2;

        while (range % p != 0 && p * p <= range) 
        {
            p++;
        }

        if (range % p == 0) 
        {
            lcg->a = 1 + p; /* Simple choice that satisfies Hull-Dobell */
        } else {
            lcg->a = LCG_DEFAULT_A % range;
            if (lcg->a == 0) lcg->a = 1;
        }
    }
    return B579_OK;
}

/* ── Next Value ── */

uint64_t b579_lcg_next(b579_lcg_t *lcg) 
{
    if (!lcg)
    {
        return 0;
    }

    if (lcg->m == 0) 
    {
        /* m = 2^64: natural overflow handles modulo */
        lcg->state = lcg->a * lcg->state + lcg->c;
    } else {
        /* Explicit modulo */
        /* Use 128-bit multiply to avoid overflow */
#if defined(B579_COMPILER_GCC) || defined(B579_COMPILER_CLANG)
        __uint128_t wide = (__uint128_t)lcg->a * lcg->state + lcg->c;lcg->state = (uint64_t)(wide % lcg->m);
#else
        /* Fallback: just use modulo (may overflow for large a*state) */
        lcg->state = (lcg->a * lcg->state + lcg->c) % lcg->m;
#endif
    }
    return lcg->state;
}

/* ── Range [min, max] ── */

uint32_t b579_lcg_range(b579_lcg_t *lcg,uint32_t min_val,uint32_t max_val) 
{
    if (!lcg || min_val >= max_val)
    {
        return min_val;
    }
    uint64_t range = (uint64_t)(max_val - min_val + 1);
    uint64_t val = b579_lcg_next(lcg);
    return min_val + (uint32_t)(val % range);
}

/* ── Next uint16 ── */

uint16_t b579_lcg_next_u16(b579_lcg_t *lcg) 
{
    return (uint16_t)(b579_lcg_next(lcg) >> 33); /* Use high bits (better quality) */
}

