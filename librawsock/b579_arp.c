#include <string.h>

#include "include/b579_rawsock_internal.h"


/* ══════════════════════════════════════════
 *  ARP Packet Structure (28 bytes)
 * ══════════════════════════════════════════ */

#define ARP_HARDWARE_ETHERNET  1
#define ARP_PROTOCOL_IPV4      0x0800
#define ARP_OP_REQUEST         1
#define ARP_OP_REPLY           2

/* Full ARP ethernet frame = 14 (eth) + 28 (arp) = 42 bytes */
#define ARP_FRAME_SIZE         42

/* ══════════════════════════════════════════
 *  Build ARP Request Frame
 * ══════════════════════════════════════════ */

static void build_arp_request(uint8_t        frame[ARP_FRAME_SIZE],
                               const uint8_t  src_mac[B579_MAC_LEN],
                               uint32_t       src_ip,
                               uint32_t       target_ip) {
    memset(frame, 0, ARP_FRAME_SIZE);

    /* ── Ethernet Header (14 bytes) ── */
    memset(frame, 0xFF, B579_MAC_LEN);          /* Dst: broadcast FF:FF:FF:FF:FF:FF */
    memcpy(frame + 6, src_mac, B579_MAC_LEN);   /* Src: our MAC */
    frame[12] = 0x08;                            /* EtherType: ARP (0x0806) */
    frame[13] = 0x06;

    /* ── ARP Header (28 bytes) ── */
    uint8_t *arp = frame + 14;

    b579_write_be16(arp + 0, ARP_HARDWARE_ETHERNET);  /* Hardware type */
    b579_write_be16(arp + 2, ARP_PROTOCOL_IPV4);      /* Protocol type */
    arp[4] = B579_MAC_LEN;                             /* Hardware addr len */
    arp[5] = 4;                                        /* Protocol addr len */
    b579_write_be16(arp + 6, ARP_OP_REQUEST);          /* Operation: request */

    /* Sender hardware + protocol address */
    memcpy(arp + 8, src_mac, B579_MAC_LEN);            /* Sender MAC */
    b579_write_be32(arp + 14, src_ip);                 /* Sender IP */

    /* Target hardware (unknown) + protocol address */
    memset(arp + 18, 0x00, B579_MAC_LEN);              /* Target MAC: 00:00:00:00:00:00 */
    b579_write_be32(arp + 24, target_ip);              /* Target IP */
}


/* ══════════════════════════════════════════
 *  Send ARP Request and Wait for Reply
 *
 *  This is the common implementation used when
 *  the system ARP cache doesn't have the entry.
 * ══════════════════════════════════════════ */

b579_result_t b579_arp_send_request(b579_rawsock_t *sock,
                                    uint32_t        target_ip,
                                    uint8_t         target_mac[B579_MAC_LEN],
                                    int             timeout_ms) {
    B579_CHECK_NULL(sock);
    B579_CHECK_NULL(target_mac);

    /* Build ARP request */
    uint8_t frame[ARP_FRAME_SIZE];
    build_arp_request(frame,
                      sock->ifinfo.mac,
                      sock->ifinfo.ipv4,
                      target_ip);

    /* Send ARP request */
    int sent = b579_rawsock_send(sock, frame, ARP_FRAME_SIZE);
    if (sent < 0) {
        b579_error_set(B579_ERR_IO, "failed to send ARP request");
        return B579_ERR_IO;
    }

    /* Wait for reply */
    uint8_t recv_buf[65536];
    b579_stopwatch_t sw;
    b579_stopwatch_start(&sw);

    while (b579_stopwatch_elapsed_ms(&sw) < (uint64_t)timeout_ms) {
        int remaining_ms = timeout_ms - (int)b579_stopwatch_elapsed_ms(&sw);
        if (remaining_ms <= 0) break;

        int len = b579_rawsock_recv(sock, recv_buf, sizeof(recv_buf),
                                    B579_MIN(remaining_ms, 100));
        if (len < ARP_FRAME_SIZE) continue;

        /* Check if ARP reply */
        if (recv_buf[12] != 0x08 || recv_buf[13] != 0x06) continue;

        uint8_t *arp = recv_buf + 14;

        /* Check operation = REPLY */
        uint16_t op = b579_read_be16(arp + 6);
        if (op != ARP_OP_REPLY) continue;

        /* Check sender IP matches target */
        uint32_t sender_ip = b579_read_be32(arp + 14);
        if (sender_ip != target_ip) continue;

        /* Extract sender MAC */
        memcpy(target_mac, arp + 8, B579_MAC_LEN);

        B579_DBG("ARP resolved: %u.%u.%u.%u → %02x:%02x:%02x:%02x:%02x:%02x",
                 (target_ip >> 24) & 0xFF, (target_ip >> 16) & 0xFF,
                 (target_ip >>  8) & 0xFF, (target_ip      ) & 0xFF,
                 target_mac[0], target_mac[1], target_mac[2],
                 target_mac[3], target_mac[4], target_mac[5]);

        return B579_OK;
    }

    b579_error_set(B579_ERR_TIMEOUT, "ARP timeout for %u.%u.%u.%u",
                   (target_ip >> 24) & 0xFF, (target_ip >> 16) & 0xFF,
                   (target_ip >>  8) & 0xFF, (target_ip      ) & 0xFF);
    return B579_ERR_TIMEOUT;
}