#include "include/b579_packet_internal.h"

b579_validation_t b579_validate(const uint8_t *frame,size_t length,const b579_parsed_t *parsed) 
{
    b579_validation_t v;
    memset(&v, 0, sizeof(v));

    if (!frame || !parsed || !parsed->is_valid) 
    {
        snprintf(v.reason, sizeof(v.reason), "invalid input");
        return v;
    }
    v.is_valid = 1;
    /* Check IP total length vs actual frame length */
    size_t expected_ip_end = B579_ETH_HDR_LEN + (parsed->has_vlan ? 4 : 0) + parsed->ip_total_len;

    if (expected_ip_end > length) 
    {
        v.is_valid = 0;
        v.lengths_consistent = 0;
        snprintf(v.reason, sizeof(v.reason),"IP total_len %u exceeds frame %zu",parsed->ip_total_len, length);
        return v;
    }
    v.lengths_consistent = 1;
    /* Verify IP checksum */
    v.ip_checksum_ok = b579_validate_ip_checksum(frame, parsed);

    /* Verify transport checksum */
    if (parsed->ip_protocol == B579_IPPROTO_TCP) 
    {
        v.transport_checksum_ok = b579_validate_tcp_checksum(frame, parsed);
    } else {
        v.transport_checksum_ok = 1; /* Skip for UDP/ICMP for now */
    }

    if (!v.ip_checksum_ok) 
    {
        v.is_valid = 0;
        snprintf(v.reason, sizeof(v.reason), "bad IP checksum");
    }
    return v;
}

int b579_validate_ip_checksum(const uint8_t *frame,const b579_parsed_t *parsed) 
{
    if (!frame || !parsed)
    {
        return 0;
    }
    size_t ip_offset = B579_ETH_HDR_LEN + (parsed->has_vlan ? 4 : 0);
    const uint8_t *ip_hdr = frame + ip_offset;
    uint16_t result = b579_checksum(ip_hdr, parsed->ip_hdr_len);
    return (result == 0) ? 1 : 0;
}

int b579_validate_tcp_checksum(const uint8_t *frame,const b579_parsed_t *parsed) 
{
    if (!frame || !parsed)
    {
        return 0;
    }

    if (parsed->ip_protocol != B579_IPPROTO_TCP)
    {
        return 0;
    }
    size_t ip_offset  = B579_ETH_HDR_LEN + (parsed->has_vlan ? 4 : 0);
    size_t tcp_offset = ip_offset + parsed->ip_hdr_len;
    size_t tcp_len    = parsed->ip_total_len - parsed->ip_hdr_len;
    uint16_t result = b579_checksum_tcp(parsed->ip_src,parsed->ip_dst,frame + tcp_offset,tcp_len);
    return (result == 0) ? 1 : 0;
}