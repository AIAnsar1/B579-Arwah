#include "include/b579_crypto_internal.h"

/* ══════════════════════════════════════════
 *  GCD — Euclidean Algorithm
 * ══════════════════════════════════════════ 
 */

uint64_t b579_gcd(uint64_t a, uint64_t b_val) 
{
    while (b_val != 0)
    {
        uint64_t t = b_val;
        b_val = a % b_val;
        a = t;
    }
    return a;
}

/* ══════════════════════════════════════════
 *  Primality Test — Trial Division
 *
 *  Good enough for values up to ~10^15.
 *  For larger values, use Miller-Rabin.
 *  Our use case: LCG modulus ≤ 2^40 (scan range).
 * ══════════════════════════════════════════ 
 */

int b579_is_prime(uint64_t n) 
{
    if (n < 2)
    {
        return 0;
    }

    if (n < 4)
    {
        return 1; /* 2 and 3 are prime */
    }

    if (n % 2 == 0 || n % 3 == 0)
    {
        return 0;
    }

    /*
     * Check divisors of form 6k ± 1 up to sqrt(n).
     * All primes > 3 are of this form.
     */
    for (uint64_t i = 5; i * i <= n; i += 6) 
    {
        if (n % i == 0 || n % (i + 2) == 0) 
        {
            return 0;
        }
    }
    return 1;
}

/* ══════════════════════════════════════════
 *  Next Prime >= n
 * ══════════════════════════════════════════ 
 */

uint64_t b579_next_prime(uint64_t n) 
{
    if (n <= 2)
    {
        return 2;
    }

    /* Make odd */
    if (n % 2 == 0)
    {
        n++;
    }

    while (!b579_is_prime(n)) 
    {
        n += 2;
    }
    return n;
}

/* ══════════════════════════════════════════
 *  Find Coprime — value coprime to n
 *
 *  For LCG: need c coprime to m.
 *  We generate candidates using the seed for determinism.
 *
 *  Algorithm:
 *    Start from seed, check GCD, increment until coprime found.
 *    Primes are always coprime to non-multiples, so we
 *    try prime candidates first.
 * ══════════════════════════════════════════ 
 */

uint64_t b579_find_coprime(uint64_t n, uint64_t seed) 
{
    if (n <= 1)
    {
        return 1;
    }

    /*
     * Strategy:
     *   1. Start with seed % n
     *   2. If coprime, done
     *   3. Otherwise, try next odd number
     *   4. Guaranteed to find one quickly
     *      (prime density ≈ 1/ln(n))
     */
    uint64_t candidate = seed % n;

    if (candidate == 0)
    {
        candidate = 1;
    }

    /* Make odd (even numbers share factor 2 with even n) */
    if (candidate % 2 == 0 && n % 2 == 0)
    {
        candidate++;
    }
    /* Search for coprime */
    uint64_t attempts = 0;

    while (b579_gcd(candidate, n) != 1) 
    {
        candidate++;

        if (candidate >= n)
        {
            candidate = 1;
        }
        attempts++;

        /* Safety: shouldn't happen, but prevent infinite loop */
        if (attempts > n) 
        {
            return 1; /* 1 is coprime to everything */
        }
    }
    return candidate;
}


