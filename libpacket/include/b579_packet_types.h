#ifndef B579_PACKET_TYPES_H
#define B579_PACKET_TYPES_H

#include "../../libplatform/include/b579_platform.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ══════════════════════════════════════════
 *  Protocol Constants
 * ══════════════════════════════════════════ 
 */

/* EtherType values */
#define B579_ETHERTYPE_IPV4    0x0800
#define B579_ETHERTYPE_IPV6    0x86DD
#define B579_ETHERTYPE_ARP     0x0806
#define B579_ETHERTYPE_VLAN    0x8100
/* IP Protocol numbers */
#define B579_IPPROTO_ICMP      1
#define B579_IPPROTO_TCP       6
#define B579_IPPROTO_UDP       17
#define B579_IPPROTO_SCTP      132
/* TCP Flags */
#define B579_TCP_FIN           0x01
#define B579_TCP_SYN           0x02
#define B579_TCP_RST           0x04
#define B579_TCP_PSH           0x08
#define B579_TCP_ACK           0x10
#define B579_TCP_URG           0x20
#define B579_TCP_ECE           0x40
#define B579_TCP_CWR           0x80
#define B579_TCP_SYNACK        (B579_TCP_SYN | B579_TCP_ACK)
/* ICMP Types */
#define B579_ICMP_ECHO_REPLY   0
#define B579_ICMP_DEST_UNREACH 3
#define B579_ICMP_ECHO_REQUEST 8
#define B579_ICMP_TIME_EXCEED  11
/* TCP Options */
#define B579_TCPOPT_EOL        0
#define B579_TCPOPT_NOP        1
#define B579_TCPOPT_MSS        2
#define B579_TCPOPT_WSCALE     3
#define B579_TCPOPT_SACK_PERM  4
#define B579_TCPOPT_TIMESTAMP  8
/* Header sizes */
#define B579_ETH_HDR_LEN       14
#define B579_IPV4_HDR_MIN      20
#define B579_IPV4_HDR_MAX      60
#define B579_IPV6_HDR_LEN      40
#define B579_TCP_HDR_MIN       20
#define B579_TCP_HDR_MAX       60
#define B579_UDP_HDR_LEN       8
#define B579_ICMP_HDR_LEN      8
#define B579_ARP_HDR_LEN       28
/* Maximum packet sizes */
#define B579_MAX_FRAME_LEN     65535
#define B579_MIN_FRAME_LEN     14       /* Ethernet header only */
#define B579_MTU_DEFAULT       1500


/* ══════════════════════════════════════════
 *  Parsed Packet — Zero-Copy Structure
 *
 *  Pointers reference the ORIGINAL buffer.
 *  No memory allocation needed for parsing.
 *  Valid only as long as the source buffer lives.
 *
 *  Pattern: Flyweight — shares data with source buffer
 * ══════════════════════════════════════════ 
 */

typedef struct {
    /* ── Layer 2: Ethernet ── */
    const uint8_t *eth_dst;          /* Pointer → dst MAC in buffer */
    const uint8_t *eth_src;          /* Pointer → src MAC in buffer */
    uint16_t       eth_type;         /* EtherType (host byte order) */
    /* ── Layer 3: IP ── */
    uint8_t        ip_version;       /* 4 or 6 */
    uint8_t        ip_protocol;      /* TCP=6, UDP=17, ICMP=1 */
    uint8_t        ip_ttl;           /* Time To Live */
    uint8_t        ip_tos;           /* Type of Service / DSCP */
    uint16_t       ip_id;            /* Identification */
    uint16_t       ip_hdr_len;       /* IP header length in bytes */
    uint16_t       ip_total_len;     /* Total IP packet length */
    uint16_t       ip_frag_offset;   /* Fragment offset */
    uint32_t       ip_src;           /* Source IP (host byte order) */
    uint32_t       ip_dst;           /* Destination IP (host byte order) */
    uint16_t       ip_checksum;      /* Original checksum from packet */
    /* ── Layer 4: TCP ── */
    uint16_t       tcp_src_port;     /* Source port */
    uint16_t       tcp_dst_port;     /* Destination port */
    uint32_t       tcp_seq;          /* Sequence number */
    uint32_t       tcp_ack;          /* Acknowledgment number */
    uint8_t        tcp_flags;        /* TCP flags bitmask */
    uint16_t       tcp_window;       /* Window size */
    uint16_t       tcp_hdr_len;      /* TCP header length in bytes */
    uint16_t       tcp_checksum;     /* Original checksum */
    uint16_t       tcp_urgent;       /* Urgent pointer */
    /* ── Layer 4: UDP ── */
    uint16_t       udp_src_port;
    uint16_t       udp_dst_port;
    uint16_t       udp_len;
    uint16_t       udp_checksum;
    /* ── Layer 4: ICMP ── */
    uint8_t        icmp_type;
    uint8_t        icmp_code;
    uint16_t       icmp_id;
    uint16_t       icmp_seq;
    /* ── Payload ── */
    const uint8_t *payload;          /* Pointer → payload in buffer */
    size_t         payload_len;      /* Payload length */
    /* ── Metadata ── */
    const uint8_t *raw;              /* Pointer → start of raw frame */
    size_t         raw_len;          /* Total frame length */
    int            is_valid;         /* 1 if parsing succeeded */
    int            has_vlan;         /* VLAN tag present */
    uint16_t       vlan_id;          /* VLAN ID if present */

} b579_parsed_t;


/* ══════════════════════════════════════════
 *  Packet Template
 *
 *  Pre-built packet with placeholders.
 *  At scan time, only patch: dst_ip, dst_port, seq, checksums.
 *  5x faster than building from scratch.
 *
 *  Pattern: Template Method — create once, apply many times
 * ══════════════════════════════════════════ 
 */

typedef struct {
    uint8_t  data[128];              /* Template bytes (max SYN with options) */
    size_t   length;                 /* Actual template length */
    size_t   offset_eth;             /* Ethernet header offset (always 0) */
    size_t   offset_ip;              /* IP header offset */
    size_t   offset_transport;       /* TCP/UDP header offset */
    /* Offsets for fields that change per-target */
    size_t   offset_ip_dst;          /* Where dst IP lives */
    size_t   offset_ip_checksum;     /* Where IP checksum lives */
    size_t   offset_ip_id;           /* Where IP identification lives */
    size_t   offset_transport_dst;   /* Where dst port lives */
    size_t   offset_transport_seq;   /* Where sequence number lives (TCP) */
    size_t   offset_transport_check; /* Where transport checksum lives */
    /* Cached values for checksum calculation */
    uint32_t src_ip;                 /* Source IP (host order) */
    uint16_t src_port;               /* Source port */
    uint8_t  ip_protocol;            /* TCP or UDP */
    size_t   transport_len;          /* Transport header length */

} b579_template_t;


/* ══════════════════════════════════════════
 *  Packet Buffer Pool
 *
 *  Pre-allocated reusable buffers.
 *  At 10M pps, we can't malloc/free per packet.
 *
 *  Pattern: Object Pool
 * ══════════════════════════════════════════ 
 */

typedef struct b579_pkt_pool b579_pkt_pool_t;

/* Individual buffer from pool */
typedef struct {
    uint8_t *data;                   /* Buffer memory */
    size_t   capacity;               /* Buffer size */
    size_t   length;                 /* Used bytes */
} b579_pkt_buf_t;


/* ══════════════════════════════════════════
 *  Validation Result
 * ══════════════════════════════════════════ 
 */

typedef struct {
    int  is_valid; /* Overall validity */
    int  ip_checksum_ok; /* IP checksum correct */
    int  transport_checksum_ok; /* TCP/UDP checksum correct */
    int  lengths_consistent; /* All length fields agree */
    char reason[128]; /* Reason if invalid */
} b579_validation_t;


#ifdef __cplusplus
}
#endif

#endif /* B579_PACKET_TYPES_H */