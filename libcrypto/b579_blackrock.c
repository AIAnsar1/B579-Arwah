#include "include/b579_crypto_internal.h"

/* ══════════════════════════════════════════
 *  Find Optimal Feistel Split
 *
 *  We need a, b such that a * b >= range.
 *  Ideally a ≈ b ≈ sqrt(range) for balanced halves.
 *  Balanced halves = better randomness.
 * ══════════════════════════════════════════ 
 */

static uint64_t find_split(uint64_t range) 
{
    if (range <= 1)
    {
        return 1;
    }
    /* Start from ceil(sqrt(range)) */
    uint64_t a = 1;

    while (a * a < range) 
    {
        a++;
    }
    return a;
}

/* ══════════════════════════════════════════
 *  Feistel Round Function
 *
 *  Must produce good avalanche effect:
 *  flipping one input bit should flip ~50% of output bits.
 *
 *  Uses splitmix64 mixing — proven good avalanche
 *  from Java's SplittableRandom.
 * ══════════════════════════════════════════ 
 */

static uint64_t round_func(uint64_t value,uint64_t seed,uint64_t range) 
{
    uint64_t r = value ^ seed;
    r = splitmix64(r);
    return r % range;
}

/* ══════════════════════════════════════════
 *  Initialize
 * ══════════════════════════════════════════ 
 */

void b579_blackrock_init(b579_blackrock_t *br,uint64_t range,uint64_t seed) 
{
    b579_blackrock_init_ex(br, range, seed, 6);
}

void b579_blackrock_init_ex(b579_blackrock_t *br,uint64_t range,uint64_t seed,uint32_t rounds) 
{
    if (!br)
    {
        return;
    }
    br->range  = range;
    br->seed   = seed;
    br->rounds = (rounds >= 3) ? rounds : 6;

    if (range <= 1) 
    {
        br->a = 1;
        br->b = 1;
        return;
    }
    br->a = find_split(range);
    br->b = (range + br->a - 1) / br->a; /* ceil(range / a) */

    /* Ensure a * b >= range */
    while (br->a * br->b < range) 
    {
        br->b++;
    }
    B579_DBG("BlackRock: range=%llu a=%llu b=%llu seed=%llu rounds=%u",(unsigned long long)range,(unsigned long long)br->a,(unsigned long long)br->b,(unsigned long long)seed,rounds);
}

/* ══════════════════════════════════════════
 *  Shuffle (Forward Permutation)
 *
 *  HOT PATH — called once per packet.
 *
 *  Cycle walking: if result lands outside [0, range),
 *  apply the permutation again. This terminates quickly
 *  because a * b is only slightly larger than range.
 * ══════════════════════════════════════════ */

uint64_t b579_blackrock_shuffle(const b579_blackrock_t *br,uint64_t index) 
{
    if (!br || br->range <= 1)
    {
        return index;
    }
    uint64_t left  = index % br->a;
    uint64_t right = index / br->a;

    for (uint32_t r = 0; r < br->rounds; r++) 
    {
        uint64_t rseed = br->seed + r;

        if (r & 1) 
        {
            right = (right + round_func(left, rseed, br->b)) % br->b;
        } else {
            left = (left + round_func(right, rseed, br->a)) % br->a;
        }
    }
    uint64_t result = right * br->a + left;

    /* Cycle walk: stay inside [0, range) */
    if (B579_UNLIKELY(result >= br->range)) 
    {
        return b579_blackrock_shuffle(br, result);
    }
    return result;
}

/* ══════════════════════════════════════════
 *  Unshuffle (Reverse Permutation)
 * ══════════════════════════════════════════ 
 */

uint64_t b579_blackrock_unshuffle(const b579_blackrock_t *br,uint64_t index) 
{
    if (!br || br->range <= 1)
    {
        return index;
    }
    uint64_t left  = index % br->a;
    uint64_t right = index / br->a;

    /* Reverse round order */
    for (int r = (int)br->rounds - 1; r >= 0; r--) 
    {
        uint64_t rseed = br->seed + (uint32_t)r;

        if (r & 1) 
        {
            uint64_t sub = round_func(left, rseed, br->b) % br->b;
            right = (right + br->b - sub) % br->b;
        } else {
            uint64_t sub = round_func(right, rseed, br->a) % br->a;
            left = (left + br->a - sub) % br->a;
        }
    }
    uint64_t result = right * br->a + left;

    if (B579_UNLIKELY(result >= br->range)) 
    {
        return b579_blackrock_unshuffle(br, result);
    }
    return result;
}
