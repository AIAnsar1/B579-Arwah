#include "include/b579_packet_internal.h"

size_t b579_build_ipv6(uint8_t *buf,const uint8_t src_ip[16],const uint8_t dst_ip[16],uint8_t next_header,uint8_t hop_limit,uint16_t payload_length) 
{
    if (!buf)
    {
        return 0;
    }
    memset(buf, 0, B579_IPV6_HDR_LEN);
    buf[0] = 0x60;                               /* Version=6 */
    b579_write_be16(buf + 4, payload_length);    /* Payload Length */
    buf[6] = next_header;                        /* Next Header */
    buf[7] = hop_limit;                          /* Hop Limit */

    if (src_ip) 
    {
        memcpy(buf + 8,  src_ip, 16);   /* Source */
    }
    
    if (dst_ip)
    {
        memcpy(buf + 24, dst_ip, 16);   /* Destination */
    }
    return B579_IPV6_HDR_LEN; /* 40 */
}