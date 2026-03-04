#include "include/b579_packet_internal.h"


size_t b579_build_icmp_echo(uint8_t *buf,uint16_t id,uint16_t seq) 
{
    if (!buf)
    {
        return 0;
    }
    memset(buf, 0, B579_ICMP_HDR_LEN);
    buf[0] = B579_ICMP_ECHO_REQUEST;    /* Type */
    buf[1] = 0;                          /* Code */
    /* buf[2..3] = checksum (filled by caller) */
    b579_write_be16(buf + 4, id);        /* Identifier */
    b579_write_be16(buf + 6, seq);       /* Sequence Number */
    return B579_ICMP_HDR_LEN; /* 8 */
}











