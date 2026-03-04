#include "include/b579_packet_internal.h"

b579_result_t b579_parse(const uint8_t *frame,size_t length,b579_parsed_t *out) 
{
    B579_CHECK_NULL(frame);
    B579_CHECK_NULL(out);
    memset(out, 0, sizeof(*out));
    out->raw     = frame;
    out->raw_len = length;

    /* ── Minimum: Ethernet header ── */
    if (B579_UNLIKELY(length < B579_ETH_HDR_LEN)) 
    {
        return B579_ERR_INVAL;
    }
    /* ── Ethernet ── */
    out->eth_dst  = frame;
    out->eth_src  = frame + 6;
    out->eth_type = b579_read_be16(frame + 12);
    const uint8_t *next = frame + B579_ETH_HDR_LEN;
    size_t remaining    = length - B579_ETH_HDR_LEN;

    /* Handle VLAN (802.1Q) */
    if (out->eth_type == B579_ETHERTYPE_VLAN) 
    {
        if (remaining < 4)
        {
            return B579_ERR_INVAL;
        }
        out->has_vlan = 1;
        out->vlan_id  = b579_read_be16(next) & 0x0FFF;
        out->eth_type = b579_read_be16(next + 2);
        next      += 4;
        remaining -= 4;
    }

    /* ── IPv4 ── */
    if (out->eth_type == B579_ETHERTYPE_IPV4) 
    {
        if (remaining < B579_IPV4_HDR_MIN)
        {
            return B579_ERR_INVAL;
        }
        out->ip_version   = (next[0] >> 4) & 0x0F;

        if (out->ip_version != 4)
        {
            return B579_ERR_INVAL;
        }
        out->ip_hdr_len   = (next[0] & 0x0F) * 4;

        if (out->ip_hdr_len < B579_IPV4_HDR_MIN)
        {
            return B579_ERR_INVAL;
        }

        if (out->ip_hdr_len > remaining)
        {
            return B579_ERR_INVAL;
        }
        out->ip_tos        = next[1];
        out->ip_total_len  = b579_read_be16(next + 2);
        out->ip_id         = b579_read_be16(next + 4);
        out->ip_frag_offset= b579_read_be16(next + 6) & 0x1FFF;
        out->ip_ttl        = next[8];
        out->ip_protocol   = next[9];
        out->ip_checksum   = b579_read_be16(next + 10);
        out->ip_src        = b579_read_be32(next + 12);
        out->ip_dst        = b579_read_be32(next + 16);
        const uint8_t *transport = next + out->ip_hdr_len;
        size_t transport_remaining = remaining - out->ip_hdr_len;

        /* ── TCP ── */
        if (out->ip_protocol == B579_IPPROTO_TCP) 
        {
            if (transport_remaining < B579_TCP_HDR_MIN)
            {
                return B579_ERR_INVAL;
            }
            out->tcp_src_port = b579_read_be16(transport);
            out->tcp_dst_port = b579_read_be16(transport + 2);
            out->tcp_seq = b579_read_be32(transport + 4);
            out->tcp_ack = b579_read_be32(transport + 8);
            out->tcp_hdr_len = ((transport[12] >> 4) & 0x0F) * 4;
            out->tcp_flags = transport[13];
            out->tcp_window = b579_read_be16(transport + 14);
            out->tcp_checksum = b579_read_be16(transport + 16);
            out->tcp_urgent = b579_read_be16(transport + 18);

            if (out->tcp_hdr_len >= B579_TCP_HDR_MIN && out->tcp_hdr_len <= transport_remaining) 
            {
                out->payload     = transport + out->tcp_hdr_len;
                out->payload_len = transport_remaining - out->tcp_hdr_len;
            }
        }
        /* ── UDP ── */
        else if (out->ip_protocol == B579_IPPROTO_UDP) 
        {
            if (transport_remaining < B579_UDP_HDR_LEN)
            {
                return B579_ERR_INVAL;
            }
            out->udp_src_port = b579_read_be16(transport);
            out->udp_dst_port = b579_read_be16(transport + 2);
            out->udp_len = b579_read_be16(transport + 4);
            out->udp_checksum = b579_read_be16(transport + 6);
            out->payload = transport + B579_UDP_HDR_LEN;
            out->payload_len = transport_remaining - B579_UDP_HDR_LEN;
        }
        /* ── ICMP ── */
        else if (out->ip_protocol == B579_IPPROTO_ICMP) 
        {
            if (transport_remaining < B579_ICMP_HDR_LEN)
            {
                return B579_ERR_INVAL;
            }
            out->icmp_type = transport[0];
            out->icmp_code = transport[1];
            out->icmp_id   = b579_read_be16(transport + 4);
            out->icmp_seq  = b579_read_be16(transport + 6);
            out->payload     = transport + B579_ICMP_HDR_LEN;
            out->payload_len = transport_remaining - B579_ICMP_HDR_LEN;
        }
        out->is_valid = 1;
        return B579_OK;
    }
    /* Non-IPv4: we parsed ethernet but not L3+ */
    return B579_ERR_INVAL;
}