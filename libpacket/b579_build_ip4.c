#include "include/b579_packet_internal.h"


size_t b579_build_ipv4(uint8_t *buf,uint32_t src_ip,uint32_t dst_ip,uint8_t protocol,uint8_t ttl,uint16_t total_length,uint16_t identification) 
{
    if (!buf)
    {
        return 0;
    }
    memset(buf, 0, B579_IPV4_HDR_MIN);
    buf[0] = 0x45;                               /* Version=4, IHL=5 (20 bytes) */
    buf[1] = 0x00;                               /* DSCP/ECN */
    b579_write_be16(buf + 2, total_length);      /* Total Length */
    b579_write_be16(buf + 4, identification);    /* Identification */
    b579_write_be16(buf + 6, 0x4000);            /* Flags: Don't Fragment */
    buf[8] = ttl;                                /* TTL */
    buf[9] = protocol;                           /* Protocol */
    /* buf[10..11] = checksum (filled later) */
    b579_write_be32(buf + 12, src_ip);           /* Source IP */
    b579_write_be32(buf + 16, dst_ip);           /* Destination IP */
    /* Calculate checksum */
    uint16_t cksum = b579_checksum(buf, B579_IPV4_HDR_MIN);
    memcpy(buf + 10, &cksum, 2);
    return B579_IPV4_HDR_MIN; /* 20 */
}



