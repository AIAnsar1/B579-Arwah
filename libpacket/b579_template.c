#include "include/b579_packet_internal.h"

/* ══════════════════════════════════════════
 *  Create SYN Template
 * ══════════════════════════════════════════ */

b579_result_t b579_template_create_syn(b579_template_t *tmpl,const uint8_t src_mac[6],const uint8_t dst_mac[6],uint32_t src_ip,uint16_t src_port,uint8_t ttl) 
{
    B579_CHECK_NULL(tmpl);
    B579_CHECK_NULL(src_mac);
    B579_CHECK_NULL(dst_mac);
    memset(tmpl, 0, sizeof(*tmpl));
    uint8_t *pkt = tmpl->data;
    size_t pos = 0;
    /* Cache values for checksum calculation */
    tmpl->src_ip      = src_ip;
    tmpl->src_port    = src_port;
    tmpl->ip_protocol = B579_IPPROTO_TCP;
    /* ── Ethernet (14 bytes) ── */
    tmpl->offset_eth = pos;
    pos += b579_build_eth(pkt + pos, dst_mac, src_mac, B579_ETHERTYPE_IPV4);
    /* ── IPv4 (20 bytes) ── */
    tmpl->offset_ip = pos;
    /* Total length: IP(20) + TCP(24 with MSS option) = 44 */
    pos += b579_build_ipv4(pkt + pos, src_ip, 0 /*placeholder*/,B579_IPPROTO_TCP, ttl, 44, 0);
    /* ── TCP SYN with MSS (24 bytes) ── */
    tmpl->offset_transport = pos;
    pos += b579_build_tcp_syn(pkt + pos, src_port, 0 /*placeholder*/,0 /*placeholder seq*/, 1460 /*MSS*/);
    tmpl->length        = pos;
    tmpl->transport_len = pos - tmpl->offset_transport;
    /* Record offsets of fields that change per target */
    tmpl->offset_ip_dst           = tmpl->offset_ip + 16;
    tmpl->offset_ip_checksum      = tmpl->offset_ip + 10;
    tmpl->offset_ip_id            = tmpl->offset_ip + 4;
    tmpl->offset_transport_dst    = tmpl->offset_transport + 2;
    tmpl->offset_transport_seq    = tmpl->offset_transport + 4;
    tmpl->offset_transport_check  = tmpl->offset_transport + 16;
    B579_DBG("SYN template created: %zu bytes, src=%u.%u.%u.%u:%u",tmpl->length,(src_ip >> 24) & 0xFF, (src_ip >> 16) & 0xFF,(src_ip >>  8) & 0xFF, (src_ip) & 0xFF,src_port);
    return B579_OK;
}

/* ══════════════════════════════════════════
 *  Create UDP Template
 * ══════════════════════════════════════════ 
 */

b579_result_t b579_template_create_udp(b579_template_t *tmpl,const uint8_t src_mac[6],const uint8_t dst_mac[6],uint32_t src_ip,uint16_t src_port,uint8_t ttl) 
{
    B579_CHECK_NULL(tmpl);
    B579_CHECK_NULL(src_mac);
    B579_CHECK_NULL(dst_mac);
    memset(tmpl, 0, sizeof(*tmpl));
    uint8_t *pkt = tmpl->data;
    size_t pos = 0;
    tmpl->src_ip      = src_ip;
    tmpl->src_port    = src_port;
    tmpl->ip_protocol = B579_IPPROTO_UDP;
    /* Ethernet */
    tmpl->offset_eth = pos;
    pos += b579_build_eth(pkt + pos, dst_mac, src_mac, B579_ETHERTYPE_IPV4);
    /* IPv4 — total length: IP(20) + UDP(8) = 28 */
    tmpl->offset_ip = pos;
    pos += b579_build_ipv4(pkt + pos, src_ip, 0, B579_IPPROTO_UDP, ttl, 28, 0);
    /* UDP */
    tmpl->offset_transport = pos;
    pos += b579_build_udp(pkt + pos, src_port, 0, 0);
    tmpl->length = pos;
    tmpl->transport_len = pos - tmpl->offset_transport;
    tmpl->offset_ip_dst = tmpl->offset_ip + 16;
    tmpl->offset_ip_checksum = tmpl->offset_ip + 10;
    tmpl->offset_ip_id = tmpl->offset_ip + 4;
    tmpl->offset_transport_dst = tmpl->offset_transport + 2;
    tmpl->offset_transport_seq = 0; /* UDP has no seq */
    tmpl->offset_transport_check = tmpl->offset_transport + 6;
    return B579_OK;
}

/* ══════════════════════════════════════════
 *  Create ICMP Echo Template
 * ══════════════════════════════════════════ 
 */

b579_result_t b579_template_create_icmp(b579_template_t *tmpl,const uint8_t src_mac[6],const uint8_t dst_mac[6],uint32_t src_ip,uint8_t ttl) 
{
    B579_CHECK_NULL(tmpl);
    B579_CHECK_NULL(src_mac);
    B579_CHECK_NULL(dst_mac);
    memset(tmpl, 0, sizeof(*tmpl));
    uint8_t *pkt = tmpl->data;
    size_t pos = 0;
    tmpl->src_ip      = src_ip;
    tmpl->ip_protocol = B579_IPPROTO_ICMP;
    /* Ethernet */
    tmpl->offset_eth = pos;
    pos += b579_build_eth(pkt + pos, dst_mac, src_mac, B579_ETHERTYPE_IPV4);
    /* IPv4 — total length: IP(20) + ICMP(8) = 28 */
    tmpl->offset_ip = pos;
    pos += b579_build_ipv4(pkt + pos, src_ip, 0, B579_IPPROTO_ICMP, ttl, 28, 0);
    /* ICMP Echo */
    tmpl->offset_transport = pos;
    pos += b579_build_icmp_echo(pkt + pos, 0, 0);
    tmpl->length = pos;
    tmpl->transport_len = pos - tmpl->offset_transport;
    tmpl->offset_ip_dst = tmpl->offset_ip + 16;
    tmpl->offset_ip_checksum = tmpl->offset_ip + 10;
    tmpl->offset_ip_id = tmpl->offset_ip + 4;
    tmpl->offset_transport_check = tmpl->offset_transport + 2;
    return B579_OK;
}

/* ══════════════════════════════════════════
 *  Apply Template — THE HOT PATH
 *
 *  Called once per target IP:port combination.
 *  At 10M pps, this runs 10 million times per second.
 *  EVERY NANOSECOND COUNTS HERE.
 * ══════════════════════════════════════════ 
 */

void b579_template_apply(const b579_template_t *tmpl,uint8_t *out,uint32_t dst_ip,uint16_t dst_port,uint32_t seq_num) 
{
    /* Step 1: copy template (fast memcpy, typically 58-70 bytes) */
    memcpy(out, tmpl->data, tmpl->length);
    /* Step 2: patch destination IP */
    b579_write_be32(out + tmpl->offset_ip_dst, dst_ip);

    /* Step 3: patch destination port (TCP/UDP only) */
    if (tmpl->offset_transport_dst > 0) 
    {
        b579_write_be16(out + tmpl->offset_transport_dst, dst_port);
    }

    /* Step 4: patch sequence number (TCP only) */
    if (tmpl->offset_transport_seq > 0) 
    {
        b579_write_be32(out + tmpl->offset_transport_seq, seq_num);
    }
    /* Step 5: recalculate IP checksum */
    /* Zero the checksum field first */
    out[tmpl->offset_ip_checksum]     = 0;
    out[tmpl->offset_ip_checksum + 1] = 0;

    uint16_t ip_cksum = b579_checksum(out + tmpl->offset_ip,B579_IPV4_HDR_MIN);
    memcpy(out + tmpl->offset_ip_checksum, &ip_cksum, 2);
    /* Step 6: recalculate transport checksum */
    out[tmpl->offset_transport_check]     = 0;
    out[tmpl->offset_transport_check + 1] = 0;

    if (tmpl->ip_protocol == B579_IPPROTO_TCP) 
    {
        uint16_t tcp_cksum = b579_checksum_tcp(tmpl->src_ip, dst_ip,out + tmpl->offset_transport,tmpl->transport_len);
        memcpy(out + tmpl->offset_transport_check, &tcp_cksum, 2);

    } else if (tmpl->ip_protocol == B579_IPPROTO_UDP) {
        uint16_t udp_cksum = b579_checksum_udp(tmpl->src_ip, dst_ip,out + tmpl->offset_transport,tmpl->transport_len);
        memcpy(out + tmpl->offset_transport_check, &udp_cksum, 2);

    } else if (tmpl->ip_protocol == B579_IPPROTO_ICMP) {
        uint16_t icmp_cksum = b579_checksum_icmp(out + tmpl->offset_transport,tmpl->transport_len);
        memcpy(out + tmpl->offset_transport_check, &icmp_cksum, 2);
    }
}
