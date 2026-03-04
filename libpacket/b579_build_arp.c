#include "include/b579_packet_internal.h"

size_t b579_build_arp_request(uint8_t *buf,const uint8_t src_mac[6],uint32_t src_ip,uint32_t target_ip) 
{
    if (!buf || !src_mac)
    {
        return 0;
    }
    /* Ethernet header */
    size_t pos = 0;
    memset(buf, 0xFF, 6);                /* Dst: broadcast */
    memcpy(buf + 6, src_mac, 6);         /* Src: our MAC */
    b579_write_be16(buf + 12, B579_ETHERTYPE_ARP);
    pos = B579_ETH_HDR_LEN;
    /* ARP header */
    uint8_t *arp = buf + pos;
    b579_write_be16(arp + 0, 1);                 /* Hardware: Ethernet */
    b579_write_be16(arp + 2, B579_ETHERTYPE_IPV4); /* Protocol: IPv4 */
    arp[4] = 6;                                  /* HW addr len */
    arp[5] = 4;                                  /* Proto addr len */
    b579_write_be16(arp + 6, 1);                 /* Operation: Request */
    memcpy(arp + 8, src_mac, 6);                 /* Sender MAC */
    b579_write_be32(arp + 14, src_ip);           /* Sender IP */
    memset(arp + 18, 0, 6);                      /* Target MAC: unknown */
    b579_write_be32(arp + 24, target_ip);        /* Target IP */
    return B579_ETH_HDR_LEN + B579_ARP_HDR_LEN; /* 42 */
}












