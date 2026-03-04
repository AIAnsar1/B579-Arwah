#ifndef B579_PACKET_INTERNAL_H
#define B579_PACKET_INTERNAL_H

#include <string.h>

#include "b579_packet.h"


/* Pointer offset helper */
#define PKT_AT(buf, offset) ((buf) + (offset))
/* Minimum Ethernet+IP+TCP */
#define B579_MIN_TCP_FRAME (B579_ETH_HDR_LEN + B579_IPV4_HDR_MIN + B579_TCP_HDR_MIN)
/* Minimum Ethernet+IP+UDP */
#define B579_MIN_UDP_FRAME (B579_ETH_HDR_LEN + B579_IPV4_HDR_MIN + B579_UDP_HDR_LEN)
/* Forward declaration: SIMD checksum (defined in checksum_simd.c) */
uint16_t b579_checksum_simd(const void *data, size_t len);

/* Runtime SIMD detection result */
extern int b579_has_avx2;
extern int b579_has_sse4;

#endif /* B579_PACKET_INTERNAL_H */