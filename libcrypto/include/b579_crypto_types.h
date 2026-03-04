#ifndef B579_CRYPTO_TYPES_H
#define B579_CRYPTO_TYPES_H

#include "../../libplatform/include/b579_platform.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ══════════════════════════════════════════
 *  BlackRock Cipher State
 *
 *  Feistel network that creates a bijective mapping:
 *    [0, range) → [0, range)
 *
 *  Every input maps to a UNIQUE output (permutation).
 *  No storage needed — pure computation.
 *
 *  This is THE key to scanning IPs in random order
 *  without storing a shuffled list.
 * ══════════════════════════════════════════ 
 */

typedef struct {
    uint64_t range;      /* Total number of elements [0, range) */
    uint64_t a;          /* Feistel split: left half size */
    uint64_t b;          /* Feistel split: right half size (a * b >= range) */
    uint64_t seed;       /* Random seed */
    uint32_t rounds;     /* Number of Feistel rounds (default: 6) */
} b579_blackrock_t;


/* ══════════════════════════════════════════
 *  SipHash Key
 *
 *  128-bit key for SipHash-2-4.
 *  Must be kept secret — if attacker knows the key,
 *  they can predict SYN cookies.
 * ══════════════════════════════════════════ 
 */

typedef struct {
    uint64_t k0;
    uint64_t k1;
} b579_siphash_key_t;


/* ══════════════════════════════════════════
 *  SYN Cookie Context
 *
 *  Holds the secret key for SYN cookie generation.
 *  One context per scan session.
 *
 *  Pattern: Context Object — bundles related state
 * ══════════════════════════════════════════ 
 */

typedef struct {
    b579_siphash_key_t key;      /* Secret hashing key */
    uint64_t           secret;   /* Additional secret for mixing */
} b579_syn_cookie_ctx_t;


/* ══════════════════════════════════════════
 *  LCG — Linear Congruential Generator
 *
 *  Fast PRNG: next = (a * state + c) % m
 *  NOT cryptographically secure.
 *  Used for: port selection, timing jitter, IP ID field.
 *
 *  Parameters must satisfy Hull-Dobell theorem:
 *    1. c and m are coprime
 *    2. a-1 is divisible by all prime factors of m
 *    3. If m is divisible by 4, a-1 must be too
 * ══════════════════════════════════════════ 
 */


typedef struct {
    uint64_t state;      /* Current state */
    uint64_t a;          /* Multiplier */
    uint64_t c;          /* Increment */
    uint64_t m;          /* Modulus (0 = use 2^64, no modulo needed) */
} b579_lcg_t;


/* ══════════════════════════════════════════
 *  Xorshift128+ State
 *
 *  Faster than LCG, better statistical properties.
 *  Period: 2^128 - 1
 *  Passes BigCrush statistical tests.
 *
 *  Used for: high-frequency random values where
 *  LCG quality is insufficient.
 * ══════════════════════════════════════════ 
 */

typedef struct {
    uint64_t s0;
    uint64_t s1;
} b579_xorshift_t;


/* ══════════════════════════════════════════
 *  Entropy Source
 * ══════════════════════════════════════════ 
 */

/* Maximum bytes we can request at once */
#define B579_ENTROPY_MAX  256


#ifdef __cplusplus
}
#endif

#endif /* B579_CRYPTO_TYPES_H */