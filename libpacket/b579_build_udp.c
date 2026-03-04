#include "include/b579_packet_internal.h"

size_t b579_build_udp(uint8_t *buf,uint16_t src_port,uint16_t dst_port,uint16_t payload_len) 
{
    if (!buf)
    {
        return 0;
    }
    memset(buf, 0, B579_UDP_HDR_LEN);
    uint16_t total = B579_UDP_HDR_LEN + payload_len;
    b579_write_be16(buf + 0, src_port);
    b579_write_be16(buf + 2, dst_port);
    b579_write_be16(buf + 4, total);
    /* buf[6..7] = checksum (filled by caller) */
    return B579_UDP_HDR_LEN; /* 8 */
}








