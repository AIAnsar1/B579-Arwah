
#ifndef B579_CRYPTO_INTERNAL_H
#define B579_CRYPTO_INTERNAL_H

#include "b579_crypto.h"

/* Rotate left for 64-bit values */
#define ROTL64(x, b) (((x) << (b)) | ((x) >> (64 - (b))))

/* Splitmix64 constants (good avalanche) */
#define SPLITMIX_C1  0x9E3779B97F4A7C15ULL
#define SPLITMIX_C2  0xBF58476D1CE4E5B9ULL
#define SPLITMIX_C3  0x94D049BB133111EBULL

/* Mix function: good avalanche, used in BlackRock rounds */
B579_INLINE uint64_t splitmix64(uint64_t x) 
{
    x ^= x >> 30;
    x *= SPLITMIX_C2;
    x ^= x >> 27;
    x *= SPLITMIX_C3;
    x ^= x >> 31;
    return x;
}

#endif /* B579_CRYPTO_INTERNAL_H */