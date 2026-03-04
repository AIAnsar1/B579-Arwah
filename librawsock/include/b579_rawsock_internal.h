#pragma once

#ifndef B579_RAWSOCK_INTERNAL_H
#define B579_RAWSOCK_INTERNAL_H

#include "b579_rawsock.h"

/*
 * B-579 Arwah — Raw Socket Internals
 *
 * PRIVATE header — NOT part of public API.
 * Only included by librawsock .c files.
 *
 * Contains:
 *   - vtable (function pointer table for polymorphism)
 *   - Internal adapter structure
 *   - Forward declarations of backend functions
 *
 * Pattern: Strategy — vtable enables runtime backend selection
 * Pattern: Opaque Pointer — users never see struct b579_rawsock
 */



/* ══════════════════════════════════════════
 *  Virtual Function Table (C polymorphism)
 *
 *  Each backend fills this table with its own
 *  implementations. The dispatcher (rawsock.c)
 *  calls through these function pointers.
 *
 *  This is equivalent to a C++ virtual class
 *  or a Rust trait object.
 * ══════════════════════════════════════════ 
 */

typedef struct {
    /* Backend identity */
    const char *name;        /* "libpcap", "AF_PACKET", etc. */
    b579_backend_t type;        /* Enum value */
    /* Lifecycle */
    b579_result_t (*open)(b579_rawsock_t *sock,const b579_rawsock_config_t *config);
    void (*close)(b579_rawsock_t *sock);
    /* I/O */
    int (*send)(b579_rawsock_t *sock,const uint8_t *frame, size_t length);
    int (*recv)(b579_rawsock_t *sock,uint8_t *buf, size_t buf_size,int timeout_ms);
    /* Filter */
    b579_result_t (*set_filter)(b579_rawsock_t *sock,const char *filter_expr);
    /* Info */
    int (*get_fd)(const b579_rawsock_t *sock);
} b579_backend_vtable_t;


/* ══════════════════════════════════════════
 *  Internal Adapter Structure
 *
 *  This is what b579_rawsock_t actually points to.
 *  Users only see the opaque typedef.
 * ══════════════════════════════════════════ 
 */

struct b579_rawsock {
    /* ── Backend dispatch ── */
    const b579_backend_vtable_t *vtable;
    /* ── Configuration (copy of what user passed) ── */
    b579_rawsock_config_t config;
    /* ── Interface info (resolved at open time) ── */
    b579_ifinfo_t ifinfo;
    /* ── Backend-specific handle ── */
    /* Each backend stores its own data here */
    void *handle;    /* e.g., pcap_t*, PF_RING handle */
    int   fd;        /* File descriptor (if applicable) */
    /* ── Statistics (atomic for thread safety) ── */
    b579_atomic_u64 stat_pkts_sent;
    b579_atomic_u64 stat_pkts_recv;
    b579_atomic_u64 stat_bytes_sent;
    b579_atomic_u64 stat_bytes_recv;
    b579_atomic_u64 stat_errors_send;
    b579_atomic_u64 stat_errors_recv;
    b579_atomic_u64 stat_dropped;
    /* ── Rate calculation ── */
    uint64_t rate_last_time_ns;
    uint64_t rate_last_pkts_sent;
    uint64_t rate_last_pkts_recv;
};


/* ══════════════════════════════════════════
 *  Backend Registration
 *
 *  Each backend_*.c file defines a global vtable.
 *  rawsock.c references them for backend selection.
 *
 *  Pattern: OCP — add new backend without changing rawsock.c
 *                 (just add extern + entry in select function)
 * ══════════════════════════════════════════ */

/* Each backend declares its vtable as extern */
#ifdef B579_OS_LINUX
    extern const b579_backend_vtable_t b579_vtable_afpacket;
#endif

#if defined(B579_OS_MACOS) || defined(B579_OS_FREEBSD)
    extern const b579_backend_vtable_t b579_vtable_bpf;
#endif

#ifdef B579_OS_WINDOWS
    extern const b579_backend_vtable_t b579_vtable_npcap;
#endif

/* Always available (links against system libpcap) */
extern const b579_backend_vtable_t b579_vtable_pcap;

/* Optional — compile with -DHAVE_PFRING */
#ifdef HAVE_PFRING
    extern const b579_backend_vtable_t b579_vtable_pfring;
#endif


/* ══════════════════════════════════════════
 *  Forward Declarations: OS-specific utilities
 *
 *  Implemented in ifutils_*.c, route_*.c, arp_*.c
 * ══════════════════════════════════════════ 
 */

/* Interface utils */
b579_result_t b579_if_get_os(const char *ifname, b579_ifinfo_t *info);
int b579_if_list_os(b579_ifinfo_t *list, size_t max_count);

/* Routing */
b579_result_t b579_route_get_os(uint32_t dst_ip, b579_route_t *route);
int b579_route_list_os(b579_route_t *list, size_t max_count);

/* ARP */
b579_result_t b579_arp_cache_lookup_os(uint32_t target_ip,uint8_t target_mac[B579_MAC_LEN]);
b579_result_t b579_arp_send_request(b579_rawsock_t *sock,uint32_t target_ip,uint8_t target_mac[B579_MAC_LEN],int timeout_ms);

/* ══════════════════════════════════════════
 *  Internal Helpers
 * ══════════════════════════════════════════ 
 */

/* Allocate and zero-init a new adapter structure */
b579_rawsock_t *b579_rawsock_alloc(void);

/* Record a sent packet in statistics */
B579_INLINE void b579_rawsock_stat_sent(b579_rawsock_t *sock,size_t bytes) 
{
    b579_atomic_inc(&sock->stat_pkts_sent);
    b579_atomic_add(&sock->stat_bytes_sent, bytes);
}

/* Record a received packet in statistics */
B579_INLINE void b579_rawsock_stat_recv(b579_rawsock_t *sock,size_t bytes) 
{
    b579_atomic_inc(&sock->stat_pkts_recv);
    b579_atomic_add(&sock->stat_bytes_recv, bytes);
}

/* Record a send error */
B579_INLINE void b579_rawsock_stat_send_err(b579_rawsock_t *sock) 
{
    b579_atomic_inc(&sock->stat_errors_send);
}

/* Record a recv error */
B579_INLINE void b579_rawsock_stat_recv_err(b579_rawsock_t *sock) 
{
    b579_atomic_inc(&sock->stat_errors_recv);
}


#endif /* B579_RAWSOCK_INTERNAL_H */





















