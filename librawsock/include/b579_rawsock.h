#pragma once


#ifndef B579_RAWSOCK_H
#define B579_RAWSOCK_H

#include "b579_rawsock_types.h"

/*
 * B-579 Arwah — Raw Socket API
 *
 * Unified interface for sending/receiving raw ethernet frames
 * across all supported platforms and backends.
 *
 * Architecture:
 *   Application → rawsock.h (this API)
 *                    → rawsock.c (dispatcher)
 *                        → backend_pcap.c    (libpcap)
 *                        → backend_afpacket.c (Linux)
 *                        → backend_bpf.c     (macOS/FreeBSD)
 *                        → backend_npcap.c   (Windows)
 *                        → backend_pfring.c  (optional)
 *
 * Pattern: Facade — single header for everything
 * Pattern: Strategy — backend selected at runtime
 *
 * Usage:
 *   #include "rawsock.h"
 *
 *   b579_rawsock_config_t cfg = B579_RAWSOCK_CONFIG_DEFAULT;
 *   cfg.ifname = "eth0";
 *
 *   b579_rawsock_t *sock = b579_rawsock_open(&cfg);
 *   b579_rawsock_send(sock, packet, length);
 *   b579_rawsock_close(sock);
 */

#ifdef __cplusplus
extern "C" {
#endif

/* ══════════════════════════════════════════
 *  Library Lifecycle
 *
 *  Pattern: RAII — init before use, shutdown after done
 * ══════════════════════════════════════════ 
 */

/* Initialize rawsock subsystem (call once at startup) */
b579_result_t b579_rawsock_init(void);
/* Shutdown rawsock subsystem */
void b579_rawsock_shutdown(void);


/* ══════════════════════════════════════════
 *  Adapter Lifecycle
 *
 *  Pattern: RAII — open/close pair
 *  Every open() MUST have a matching close()
 * ══════════════════════════════════════════ 
 */

/* Open raw socket adapter with given configuration */
/* Returns NULL on failure (check b579_error_last_msg()) */
b579_rawsock_t *b579_rawsock_open(const b579_rawsock_config_t *config);
/* Close adapter and free all resources */
void b579_rawsock_close(b579_rawsock_t *sock);


/* ══════════════════════════════════════════
 *  Send / Receive
 *
 *  send: raw ethernet frame (including ethernet header)
 *  recv: raw ethernet frame with timeout
 * ══════════════════════════════════════════ 
 */

/* Send raw ethernet frame */
/* Returns bytes sent on success, negative on error */
B579_WARN_UNUSED int b579_rawsock_send(b579_rawsock_t *sock,const uint8_t *frame,size_t length);

/* Send multiple frames in one call (batch mode) */
/* Returns number of frames successfully sent */
B579_WARN_UNUSED int b579_rawsock_send_batch(b579_rawsock_t *sock,const uint8_t **frames,const size_t *lengths,size_t count);

/* Receive one raw ethernet frame */
/* Returns bytes received, 0 on timeout, negative on error */
B579_WARN_UNUSED int b579_rawsock_recv(b579_rawsock_t *sock,uint8_t *buf, size_t buf_size, int timeout_ms);


/* ══════════════════════════════════════════
 *  Adapter Information
 * ══════════════════════════════════════════ 
 */

/* Get which backend this adapter is using */
b579_backend_t b579_rawsock_get_backend(const b579_rawsock_t *sock);
/* Get backend name as string ("libpcap", "AF_PACKET", etc.) */
const char *b579_rawsock_get_backend_name(const b579_rawsock_t *sock);
/* Get the underlying file descriptor (for poll/epoll integration) */
/* Returns -1 if not applicable (e.g., Windows) */
int b579_rawsock_get_fd(const b579_rawsock_t *sock);
/* Get adapter's interface info */
b579_result_t b579_rawsock_get_ifinfo(const b579_rawsock_t *sock,b579_ifinfo_t *info);


/* ══════════════════════════════════════════
 *  Statistics
 * ══════════════════════════════════════════ */

/* Get current statistics (thread-safe, atomic reads) */
b579_rawsock_stats_t b579_rawsock_get_stats(const b579_rawsock_t *sock);
/* Reset statistics counters to zero */
void b579_rawsock_reset_stats(b579_rawsock_t *sock);


/* ══════════════════════════════════════════
 *  Receive Filter
 *
 *  Set BPF filter to capture only relevant packets.
 *  Without filter, receiver gets ALL traffic including
 *  our own sent packets — terrible for performance.
 *
 *  For scanning: filter = "tcp and tcp[13] & 0x12 = 0x12"
 *  This captures only SYN-ACK responses.
 * ══════════════════════════════════════════ 
 */

/* Set BPF filter expression (pcap filter syntax) */
b579_result_t b579_rawsock_set_filter(b579_rawsock_t *sock,const char *filter_expr);
/* Predefined filters for common scan types */
b579_result_t b579_rawsock_filter_synack(b579_rawsock_t *sock,uint16_t src_port);
b579_result_t b579_rawsock_filter_tcp(b579_rawsock_t *sock);
b579_result_t b579_rawsock_filter_icmp(b579_rawsock_t *sock);


/* ══════════════════════════════════════════
 *  Network Interface Discovery
 *
 *  Standalone functions — don't need an open adapter.
 * ══════════════════════════════════════════ 
 */

/* Get info about specific interface by name */
b579_result_t b579_if_get(const char *ifname,b579_ifinfo_t *info);
/* List all available network interfaces */
/* Returns number of interfaces found, negative on error */
/* Caller provides array and max_count */
int b579_if_list(b579_ifinfo_t *list,size_t max_count);

/* Find first non-loopback, UP interface */
/* Returns B579_OK and fills info, or B579_ERR if none found */
b579_result_t b579_if_find_default(b579_ifinfo_t *info);


/* ══════════════════════════════════════════
 *  Routing
 *
 *  Find how to reach a destination IP.
 *  Critical for scanning: need gateway MAC for off-subnet targets.
 * ══════════════════════════════════════════ 
 */

/* Get route for specific destination IP */
b579_result_t b579_route_get(uint32_t dst_ip,b579_route_t *route);

/* Get default gateway */
b579_result_t b579_route_get_default(b579_route_t *route);

/* List all routes */
int b579_route_list(b579_route_t *list,size_t max_count);


/* ══════════════════════════════════════════
 *  ARP Resolution
 *
 *  Resolve IPv4 address to MAC address.
 *  Needed to fill ethernet header destination MAC.
 *
 *  For scanning:
 *    1. Find default gateway IP (b579_route_get_default)
 *    2. Resolve gateway IP to MAC (b579_arp_resolve)
 *    3. Use gateway MAC as dst in all packets
 * ══════════════════════════════════════════ 
 */

/* Resolve IP to MAC address */
/* Tries system ARP cache first, then sends ARP request */
/* Blocks up to timeout_ms milliseconds */
b579_result_t b579_arp_resolve(b579_rawsock_t *sock,uint32_t target_ip,uint8_t target_mac[B579_MAC_LEN],int timeout_ms);
/* Look up IP in system ARP cache (no network traffic) */
b579_result_t b579_arp_cache_lookup(uint32_t  target_ip,uint8_t   target_mac[B579_MAC_LEN]);


/* ══════════════════════════════════════════
 *  Utility — backend availability check
 * ══════════════════════════════════════════ 
 */

/* Check if a specific backend is available on this system */
int b579_rawsock_backend_available(b579_backend_t backend);

/* Get list of available backends as comma-separated string */
/* Example: "AF_PACKET, libpcap" */
const char *b579_rawsock_available_backends(void);


#ifdef __cplusplus
}
#endif

#endif /* B579_RAWSOCK_H */


















