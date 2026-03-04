#include "include/b579_packet_internal.h"

size_t b579_build_tcp(uint8_t *buf,uint16_t src_port,uint16_t dst_port,uint32_t seq_num,uint32_t ack_num,uint8_t flags,uint16_t window) 
{
    if (!buf)
    {
        return 0;
    }
    memset(buf, 0, B579_TCP_HDR_MIN);
    b579_write_be16(buf + 0,  src_port);     /* Source Port */
    b579_write_be16(buf + 2,  dst_port);     /* Destination Port */
    b579_write_be32(buf + 4,  seq_num);      /* Sequence Number */
    b579_write_be32(buf + 8,  ack_num);      /* Acknowledgment Number */
    buf[12] = 0x50;                          /* Data Offset=5 (20 bytes), Reserved */
    buf[13] = flags;                         /* Flags */
    b579_write_be16(buf + 14, window);       /* Window */
    /* buf[16..17] = checksum (filled by caller) */
    /* buf[18..19] = urgent pointer = 0 */
    return B579_TCP_HDR_MIN; /* 20 */
}

size_t b579_build_tcp_syn(uint8_t *buf,uint16_t src_port,uint16_t dst_port,uint32_t seq_num,uint16_t mss) 
{
    if (!buf)
    {
        return 0;
    }
    /* Build base TCP header */
    b579_build_tcp(buf, src_port, dst_port, seq_num, 0,B579_TCP_SYN, 65535);
    /* Data Offset = 6 (24 bytes = 20 header + 4 MSS option) */
    buf[12] = 0x60;
    /* TCP Option: MSS (Kind=2, Length=4, Value=MSS) */
    buf[20] = B579_TCPOPT_MSS;
    buf[21] = 4;
    b579_write_be16(buf + 22, mss);
    return 24; /* 20 header + 4 option */
}











