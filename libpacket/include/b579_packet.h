#ifndef B579_PACKET_H
#define B579_PACKET_H

#include "b579_packet_types.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ══════════════════════════════════════════
 *  Checksum — RFC 1071
 *
 *  HOT PATH: called per every sent AND received packet.
 *  SIMD version auto-selected at runtime.
 * ══════════════════════════════════════════ 
 */

/* Generic internet checksum */
uint16_t b579_checksum(const void *data, size_t len);
/* TCP checksum with pseudo-header */
uint16_t b579_checksum_tcp(uint32_t src_ip,uint32_t dst_ip,const void *tcp_hdr,size_t tcp_len);
/* UDP checksum with pseudo-header */
uint16_t b579_checksum_udp(uint32_t src_ip,uint32_t dst_ip,const void *udp_hdr,size_t udp_len);
/* ICMP checksum (no pseudo-header) */
uint16_t b579_checksum_icmp(const void *icmp_hdr, size_t len);
/* Initialize checksum subsystem (detect SIMD at runtime) */
b579_result_t b579_checksum_init(void);


/* ══════════════════════════════════════════
 *  Packet Template — HOT PATH
 *
 *  Create template once, apply for each target.
 *  Only patches: dst_ip, dst_port, seq_num, checksums.
 * ══════════════════════════════════════════ 
 */

/* Create SYN scan template */
b579_result_t b579_template_create_syn(b579_template_t *tmpl,const uint8_t src_mac[6],const uint8_t dst_mac[6],uint32_t src_ip,uint16_t src_port,uint8_t ttl);
/* Create UDP scan template */
b579_result_t b579_template_create_udp(b579_template_t *tmpl,const uint8_t src_mac[6],const uint8_t dst_mac[6],uint32_t src_ip,uint16_t src_port,uint8_t ttl);
/* Create ICMP echo template */
b579_result_t b579_template_create_icmp(b579_template_t *tmpl,const uint8_t src_mac[6],const uint8_t dst_mac[6],uint32_t src_ip,uint8_t ttl);
/* Apply template: fill in target-specific fields */
/* HOT PATH — called once per target (millions of times) */
void b579_template_apply(const b579_template_t *tmpl,uint8_t *out,uint32_t dst_ip,uint16_t dst_port,uint32_t seq_num);
/* Get template output size */
B579_INLINE size_t b579_template_length(const b579_template_t *tmpl) 
{
    return tmpl ? tmpl->length : 0;
}


/* ══════════════════════════════════════════
 *  Packet Parsing — HOT PATH
 *
 *  Parse raw ethernet frame into structured form.
 *  Zero allocation: all pointers reference source buffer.
 * ══════════════════════════════════════════ 
 */

/* Parse raw frame → b579_parsed_t */
b579_result_t b579_parse(const uint8_t *frame,size_t length,b579_parsed_t *out);
/* Quick check: is this a SYN-ACK response? */
B579_INLINE int b579_parse_is_synack(const b579_parsed_t *p) 
{
    return p && p->is_valid && p->ip_protocol == B579_IPPROTO_TCP && (p->tcp_flags & B579_TCP_SYNACK) == B579_TCP_SYNACK;
}

/* Quick check: is this a RST? */
B579_INLINE int b579_parse_is_rst(const b579_parsed_t *p) 
{
    return p && p->is_valid &&p->ip_protocol == B579_IPPROTO_TCP && (p->tcp_flags & B579_TCP_RST);
}

/* Quick check: is this an ICMP unreachable? */
B579_INLINE int b579_parse_is_icmp_unreach(const b579_parsed_t *p) 
{
    return p && p->is_valid && p->ip_protocol == B579_IPPROTO_ICMP && p->icmp_type == B579_ICMP_DEST_UNREACH;
}


/* ══════════════════════════════════════════
 *  Packet Validation
 *
 *  Verify checksums, lengths, protocol consistency.
 *  Used on received packets to filter out garbage.
 * ══════════════════════════════════════════ 
 */

/* Full validation of parsed packet */
b579_validation_t b579_validate(const uint8_t *frame,size_t length,const b579_parsed_t *parsed);
/* Quick checksum-only validation */
int b579_validate_ip_checksum(const uint8_t *frame,const b579_parsed_t *parsed);
int b579_validate_tcp_checksum(const uint8_t *frame,const b579_parsed_t *parsed);


/* ══════════════════════════════════════════
 *  Individual Header Builders
 *
 *  For building custom packets (ARP, special probes).
 *  Returns bytes written.
 * ══════════════════════════════════════════ 
 */

/* Ethernet header (14 bytes) */
size_t b579_build_eth(uint8_t *buf,const uint8_t dst_mac[6],const uint8_t src_mac[6],uint16_t ethertype);
/* IPv4 header (20 bytes minimum) */
size_t b579_build_ipv4(uint8_t *buf,uint32_t src_ip,uint32_t dst_ip,uint8_t protocol,uint8_t ttl,uint16_t total_length,uint16_t identification);
/* IPv6 header (40 bytes) */
size_t b579_build_ipv6(uint8_t *buf,const uint8_t src_ip[16],const uint8_t dst_ip[16],uint8_t next_header,uint8_t hop_limit,uint16_t payload_length);
/* TCP header (20 bytes minimum, up to 60 with options) */
size_t b579_build_tcp(uint8_t *buf,uint16_t src_port,uint16_t dst_port,uint32_t seq_num,uint32_t ack_num,uint8_t flags,uint16_t window);
/* TCP header with MSS option (24 bytes) */
size_t b579_build_tcp_syn(uint8_t *buf,uint16_t src_port,uint16_t dst_port,uint32_t seq_num,uint16_t mss);
/* UDP header (8 bytes) */
size_t b579_build_udp(uint8_t *buf,uint16_t src_port,uint16_t dst_port,uint16_t payload_len);
/* ICMPv4 Echo Request (8 bytes) */
size_t b579_build_icmp_echo(uint8_t *buf,uint16_t id,uint16_t seq);
/* ARP request (42 bytes: eth + arp) */
size_t b579_build_arp_request(uint8_t *buf,const uint8_t src_mac[6],uint32_t src_ip,uint32_t target_ip);


/* ══════════════════════════════════════════
 *  Packet Buffer Pool
 *
 *  Pre-allocated reusable buffers for hot path.
 *  At 10M pps, malloc/free per packet is death.
 *
 *  Pattern: Object Pool
 *
 *  Usage:
 *    pool = b579_pool_create(1024, 128);  // 1024 buffers of 128 bytes
 *    buf  = b579_pool_get(pool);
 *    // ... fill buf->data ...
 *    b579_pool_put(pool, buf);
 *    b579_pool_destroy(pool);
 * ══════════════════════════════════════════ 
 */

/* Create pool of packet buffers */
b579_pkt_pool_t *b579_pool_create(size_t num_buffers,size_t buffer_size);
/* Destroy pool and free all memory */
void b579_pool_destroy(b579_pkt_pool_t *pool);
/* Get buffer from pool (returns NULL if empty) */
b579_pkt_buf_t *b579_pool_get(b579_pkt_pool_t *pool);
/* Return buffer to pool */
void b579_pool_put(b579_pkt_pool_t *pool, b579_pkt_buf_t *buf);
/* Number of available buffers in pool */
size_t b579_pool_available(const b579_pkt_pool_t *pool);


#ifdef __cplusplus
}
#endif

#endif /* B579_PACKET_H */