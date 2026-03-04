#include <stdio.h>

#include "include/b579_rawsock_internal.h"

/*
 * B-579 Arwah — Predefined Capture Filters
 *
 * BPF filters run IN THE KERNEL, so packets that don't
 * match never reach userspace. Critical for performance.
 *
 * Without filter at 10M pps: kernel copies ALL packets
 * to userspace = CPU overload.
 *
 * With filter: only SYN-ACK responses reach us = fast.
 *
 * Principle: DRY — define common filters once, reuse everywhere
 */
b579_result_t b579_rawsock_filter_synack(b579_rawsock_t *sock,uint16_t src_port) 
{
    B579_CHECK_NULL(sock);
    char filter[256];

    if (src_port > 0) 
    {
        /*
         * Capture TCP packets where:
         *   - Destination port = our source port
         *   - TCP flags have SYN+ACK set (0x12)
         *   OR RST flag set (0x04) — for closed ports
         *
         * tcp[13] is the TCP flags byte:
         *   bit 1 = SYN (0x02)
         *   bit 4 = ACK (0x10)
         *   bit 2 = RST (0x04)
         *   SYN+ACK = 0x12
         */
        snprintf(filter, sizeof(filter),"tcp and dst port %u and (tcp[13] & 0x12 = 0x12 or tcp[13] & 0x04 = 0x04)",src_port);
    } else {
        /* No source port filter — capture all SYN-ACK and RST */
        snprintf(filter, sizeof(filter),"tcp and (tcp[13] & 0x12 = 0x12 or tcp[13] & 0x04 = 0x04)");
    }
    return b579_rawsock_set_filter(sock, filter);
}


b579_result_t b579_rawsock_filter_tcp(b579_rawsock_t *sock) 
{
    B579_CHECK_NULL(sock);
    return b579_rawsock_set_filter(sock, "tcp");
}


b579_result_t b579_rawsock_filter_icmp(b579_rawsock_t *sock) 
{
    B579_CHECK_NULL(sock);
    return b579_rawsock_set_filter(sock, "icmp");
}
































