#include "include/b579_crypto_internal.h"

/* ── Init with entropy ── */

b579_result_t b579_xorshift_init(b579_xorshift_t *xs) 
{
    B579_CHECK_NULL(xs);

    /* State must not be all-zero */
    do {
        b579_entropy_fill(xs, sizeof(*xs));
    } while (xs->s0 == 0 && xs->s1 == 0);

    return B579_OK;
}

/* ── Init with explicit seed ── */

void b579_xorshift_init_seed(b579_xorshift_t *xs,uint64_t seed0,uint64_t seed1) 
{
    if (!xs)
    {
        return;
    }
    /* Ensure non-zero state */
    xs->s0 = seed0 ? seed0 : 1;
    xs->s1 = seed1 ? seed1 : ~seed0;
}

/* ── Next Value ── */

uint64_t b579_xorshift_next(b579_xorshift_t *xs) 
{
    if (!xs)
    {
        return 0;
    }

    /*
     * xorshift128+ algorithm:
     *   s1 ^= s1 << 23
     *   s1 ^= s1 >> 17
     *   s1 ^= s0 ^ (s0 >> 26)
     *   swap s0, s1
     *   return s0 + s1
     */
    uint64_t s0 = xs->s0;
    uint64_t s1 = xs->s1;
    s1 ^= s1 << 23;
    s1 ^= s1 >> 17;
    s1 ^= s0 ^ (s0 >> 26);
    xs->s0 = xs->s1;  /* Old s1 becomes new s0 */
    xs->s1 = s1;
    return xs->s0 + xs->s1;
}

/* ── Bounded Value [0, max) ── */

uint64_t b579_xorshift_bound(b579_xorshift_t *xs, uint64_t max) 
{
    if (!xs || max == 0) return 0;
    return b579_xorshift_next(xs) % max;
}

/* ── Random Double [0.0, 1.0) ── */

double b579_xorshift_double(b579_xorshift_t *xs) 
{
    /*
     * Take top 53 bits (double has 53-bit mantissa)
     * and divide by 2^53 for uniform [0.0, 1.0)
     */
    uint64_t val = b579_xorshift_next(xs) >> 11;
    return (double)val / 9007199254740992.0; /* 2^53 */
}



