#pragma once


#ifndef B579_RAWSOCK_TYPES_H
#define B579_RAWSOCK_TYPES_H


#include "../../libplatform/include/b579_platform.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ══════════════════════════════════════════
 *  Backend Selection
 *
 *  Each backend talks to the NIC differently.
 *  AUTO picks the fastest available.
 *
 *  Speed ranking (fastest first):
 *    PFRING > AFPACKET > BPF > PCAP > NPCAP
 * ══════════════════════════════════════════ 
 */

typedef enum {
    B579_BACKEND_AUTO = 0,   /* Auto-detect best available */
    B579_BACKEND_PCAP = 1,   /* libpcap — portable, everywhere */
    B579_BACKEND_AFPACKET = 2,   /* Linux AF_PACKET — fast, no libpcap */
    B579_BACKEND_BPF = 3,   /* macOS/FreeBSD BPF — native */
    B579_BACKEND_NPCAP = 4,   /* Windows Npcap — Windows native */
    B579_BACKEND_PFRING = 5,   /* PF_RING — kernel bypass, fastest */
    B579_BACKEND_COUNT = 6    /* Total number of backends */
} b579_backend_t;


/* ══════════════════════════════════════════
 *  Adapter Configuration
 *
 *  Passed to b579_rawsock_open() to configure the adapter.
 *  Pattern: Builder — fill fields, then pass to open().
 * ══════════════════════════════════════════ 
 */

typedef struct {
    const char *ifname;          /* Interface name ("eth0", "en0") */
    b579_backend_t backend;         /* Which backend to use */
    int is_sending;      /* 1 = TX adapter, 0 = RX adapter */
    int promiscuous;     /* 1 = promiscuous mode */
    int snaplen;         /* Max bytes to capture (default: 65535) */
    int send_buf_size;   /* Socket send buffer in bytes */
    int recv_buf_size;   /* Socket recv buffer in bytes */
    int timeout_ms;      /* Recv timeout (0 = non-blocking) */
} b579_rawsock_config_t;

/* Default configuration (sensible defaults for scanning) */
#define B579_RAWSOCK_CONFIG_DEFAULT {       \
    .ifname = NULL,                  \
    .backend = B579_BACKEND_AUTO,     \
    .is_sending = 1,                     \
    .promiscuous = 1,                     \
    .snaplen = 65535,                 \
    .send_buf_size = 4 * 1024 * 1024,       \
    .recv_buf_size = 4 * 1024 * 1024,       \
    .timeout_ms = 1,                     \
}


/* ══════════════════════════════════════════
 *  Network Interface Information
 * ══════════════════════════════════════════ 
 */

#define B579_IFNAME_MAX   64
#define B579_MAC_LEN       6

typedef struct {
    char name[B579_IFNAME_MAX];  /* Interface name */
    uint8_t mac[B579_MAC_LEN];      /* MAC address */
    uint32_t ipv4;                   /* IPv4 address (host byte order) */
    uint8_t ipv6[16];               /* IPv6 address */
    uint32_t netmask;                /* IPv4 netmask (host byte order) */
    uint32_t mtu;                    /* Maximum Transmission Unit */
    int index;                  /* OS interface index */
    int is_up;                  /* Interface is UP */
    int is_loopback;            /* Is loopback interface */
    int is_running;             /* Interface has carrier */
    uint64_t speed_mbps;             /* Link speed in Mbps (0=unknown) */
} b579_ifinfo_t;


/* ══════════════════════════════════════════
 *  Route Information
 * ══════════════════════════════════════════ 
 */

typedef struct {
    uint32_t dst_ip;                 /* Destination network */
    uint32_t netmask;                /* Destination netmask */
    uint32_t gateway_ip;             /* Gateway IP (0 = direct) */
    char ifname[B579_IFNAME_MAX];/* Outgoing interface */
    int metric;                 /* Route metric (lower = preferred) */
    int is_default;             /* Is this the default route? */
} b579_route_t;


/* ══════════════════════════════════════════
 *  Adapter Statistics
 * ══════════════════════════════════════════ 
 */

typedef struct {
    uint64_t packets_sent;           /* Total packets sent */
    uint64_t packets_recv;           /* Total packets received */
    uint64_t bytes_sent;             /* Total bytes sent */
    uint64_t bytes_recv;             /* Total bytes received */
    uint64_t errors_send;            /* Send errors */
    uint64_t errors_recv;            /* Receive errors */
    uint64_t dropped;                /* Packets dropped by kernel */
    double send_rate_pps;          /* Current send rate (packets/sec) */
    double recv_rate_pps;          /* Current recv rate (packets/sec) */
} b579_rawsock_stats_t;


/* ══════════════════════════════════════════
 *  Opaque Adapter Handle
 *
 *  Pattern: Opaque Pointer (PIMPL)
 *  Users never see the internal structure.
 *  They only get a pointer to pass to API functions.
 * ══════════════════════════════════════════ 
 */

typedef struct b579_rawsock b579_rawsock_t;


#ifdef __cplusplus
}
#endif



#endif /* B579_RAWSOCK_TYPES_H */

