#ifndef B579_CRYPTO_H
#define B579_CRYPTO_H

#include "b579_crypto_types.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ══════════════════════════════════════════
 *  Entropy — Seed Generation
 *
 *  ALWAYS use this to generate seeds.
 *  Never use time() or getpid() as seeds.
 *
 *  Sources:
 *    Linux:   /dev/urandom (getrandom syscall)
 *    macOS:   /dev/urandom (arc4random)
 *    Windows: CryptGenRandom (BCryptGenRandom)
 * ══════════════════════════════════════════ 
 */

/* Fill buffer with cryptographically secure random bytes */
b579_result_t b579_entropy_fill(void *buf, size_t len);
/* Get a random uint64_t */
uint64_t b579_entropy_u64(void);
/* Get a random uint32_t */
uint32_t b579_entropy_u32(void);
/* Generate a SipHash key from entropy */
b579_result_t b579_entropy_siphash_key(b579_siphash_key_t *key);


/* ══════════════════════════════════════════
 *  BlackRock — IP Randomization
 *
 *  Bijective mapping: index → shuffled_index
 *  Properties:
 *    - Every input maps to UNIQUE output
 *    - Covers entire range [0, range)
 *    - Deterministic: same seed = same permutation
 *    - Reversible: can unshuffle
 *    - O(1) per call, no memory
 *
 *  Usage:
 *    b579_blackrock_t br;
 *    b579_blackrock_init(&br, total_targets, random_seed);
 *
 *    for (i = 0; i < total_targets; i++) {
 *        target_index = b579_blackrock_shuffle(&br, i);
 *        ip   = get_ip(target_index);
 *        port = get_port(target_index);
 *        send_syn(ip, port);
 *    }
 * ══════════════════════════════════════════ 
 */

/* Initialize BlackRock cipher */
void b579_blackrock_init(b579_blackrock_t *br,uint64_t range,uint64_t seed);
/* Encrypt: sequential → random (forward permutation) */
/* HOT PATH: called once per packet sent */
uint64_t b579_blackrock_shuffle(const b579_blackrock_t *br,uint64_t index);
/* Decrypt: random → sequential (reverse permutation) */
uint64_t b579_blackrock_unshuffle(const b579_blackrock_t *br,uint64_t index);
/* Initialize with custom round count (default: 6) */
void b579_blackrock_init_ex(b579_blackrock_t *br,uint64_t range,uint64_t seed,uint32_t rounds);


/* ══════════════════════════════════════════
 *  SipHash-2-4 — Fast Keyed Hash
 *
 *  Properties:
 *    - 64-bit output
 *    - 128-bit key
 *    - 2 rounds per message block, 4 finalization rounds
 *    - Resistant to hash-flooding attacks
 *    - Used in: SYN cookies, dedup filter, hash tables
 *
 *  Reference: https://131002.net/siphash/
 * ══════════════════════════════════════════ 
 */

/* Hash arbitrary data */
uint64_t b579_siphash(const void *data,size_t len,const b579_siphash_key_t *key);
/* Hash an IP:port pair (optimized for common case) */
/* HOT PATH: called for every received packet (dedup check) */
uint64_t b579_siphash_ipport(uint32_t ip,uint16_t port,const b579_siphash_key_t *key);
/* Hash two uint64 values (for combining hashes) */
uint64_t b579_siphash_u64(uint64_t a,uint64_t b_val,const b579_siphash_key_t *key);


/* ══════════════════════════════════════════
 *  SYN Cookie — Stateless Scan Tracking
 *
 *  Encode scan context into TCP sequence number.
 *  When SYN-ACK arrives, ack = our_seq + 1.
 *  We recompute the cookie and verify.
 *
 *  No per-connection state needed!
 *  This is what enables scanning at 10M pps
 *  with only ~50MB RAM.
 *
 *  Pattern: Context Object — ctx holds the secret
 * ══════════════════════════════════════════ 
 */

/* Initialize SYN cookie context with random secret */
b579_result_t b579_syn_cookie_init(b579_syn_cookie_ctx_t *ctx);
/* Initialize with explicit secret (for reproducible scans) */
void b579_syn_cookie_init_with_secret(b579_syn_cookie_ctx_t *ctx,uint64_t secret);
/* Generate SYN cookie (goes into TCP seq number) */
/* HOT PATH: called once per SYN packet sent */
uint32_t b579_syn_cookie_generate(const b579_syn_cookie_ctx_t *ctx,uint32_t src_ip,uint16_t src_port,uint32_t dst_ip,uint16_t dst_port);

/* Verify SYN cookie from SYN-ACK response */
/* HOT PATH: called once per SYN-ACK received */
/*
 * In the response:
 *   resp_src_ip/port = what was our dst_ip/port (target)
 *   resp_dst_ip/port = what was our src_ip/port (us)
 *   ack_num          = our original seq + 1
 *
 * Returns 1 if valid, 0 if invalid (not our scan)
 */
int b579_syn_cookie_verify(const b579_syn_cookie_ctx_t *ctx,uint32_t resp_src_ip,uint16_t resp_src_port,uint32_t resp_dst_ip,uint16_t resp_dst_port,uint32_t ack_num);


/* ══════════════════════════════════════════
 *  LCG — Linear Congruential Generator
 *
 *  Very fast PRNG. One multiply + one add per call.
 *  Good enough for: IP ID field, port randomization,
 *  timing jitter.
 *
 *  NOT for: anything security-sensitive.
 * ══════════════════════════════════════════ 
 */

/* Initialize with random seed from entropy */
b579_result_t b579_lcg_init(b579_lcg_t *lcg);
/* Initialize with explicit seed */
void b579_lcg_init_seed(b579_lcg_t *lcg, uint64_t seed);
/* Initialize for specific range with full period */
/* Finds coprime parameters so LCG visits every value in [0, range) */
b579_result_t b579_lcg_init_range(b579_lcg_t *lcg,uint64_t range,uint64_t seed);
/* Get next random uint64 */
uint64_t b579_lcg_next(b579_lcg_t *lcg);
/* Get next random value in [min, max] inclusive */
uint32_t b579_lcg_range(b579_lcg_t *lcg,uint32_t min_val,uint32_t max_val);
/* Get next random uint16 (for port numbers) */
uint16_t b579_lcg_next_u16(b579_lcg_t *lcg);


/* ══════════════════════════════════════════
 *  Xorshift128+ — Better PRNG
 *
 *  Faster than LCG on modern CPUs (instruction-level parallelism).
 *  Period: 2^128 - 1 (vs LCG's 2^64).
 *  Passes BigCrush tests (LCG fails some).
 *
 *  Use when: you need many random values quickly
 *  and LCG quality is borderline.
 * ══════════════════════════════════════════ 
 */

/* Initialize with random seed from entropy */
b579_result_t b579_xorshift_init(b579_xorshift_t *xs);
/* Initialize with explicit seed */
void b579_xorshift_init_seed(b579_xorshift_t *xs,uint64_t seed0,uint64_t seed1);
/* Get next random uint64 */
uint64_t b579_xorshift_next(b579_xorshift_t *xs);
/* Get next random value in [0, max) exclusive */
uint64_t b579_xorshift_bound(b579_xorshift_t *xs, uint64_t max);
/* Get next random double in [0.0, 1.0) */
double b579_xorshift_double(b579_xorshift_t *xs);


/* ══════════════════════════════════════════
 *  Prime Utilities
 *
 *  LCG with full period requires coprime parameters.
 *  These functions find suitable primes.
 * ══════════════════════════════════════════ 
 */

/* Test if n is prime */
int b579_is_prime(uint64_t n);
/* Find next prime >= n */
uint64_t b579_next_prime(uint64_t n);
/* Find a value coprime to n (for LCG increment) */
uint64_t b579_find_coprime(uint64_t n, uint64_t seed);
/* GCD of two numbers */
uint64_t b579_gcd(uint64_t a, uint64_t b_val);


#ifdef __cplusplus
}
#endif

#endif /* B579_CRYPTO_H */


