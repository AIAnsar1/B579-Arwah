#include "include/b579_packet_internal.h"




size_t b579_build_eth(uint8_t *buf,const uint8_t dst_mac[6],const uint8_t src_mac[6],uint16_t ethertype) 
{
    if (!buf)
    {
        return 0;
    }
    memcpy(buf,     dst_mac, 6);
    memcpy(buf + 6, src_mac, 6);
    b579_write_be16(buf + 12, ethertype);
    return B579_ETH_HDR_LEN; /* 14 */
}




























