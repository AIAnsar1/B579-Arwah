#include <stdlib.h>
#include <string.h>

#include "include/b579_rawsock_internal.h"


/*
 * B-579 Arwah — Raw Socket Dispatcher
 *
 * Central coordinator for all raw socket operations.
 * Selects the best backend and delegates all calls
 * through the vtable.
 *
 * Pattern: Factory — b579_rawsock_open creates the right backend
 * Pattern: Strategy — vtable dispatches to implementation
 * Pattern: Facade — single entry point for all operations
 * Principle: OCP — add backend = add extern + case, nothing else changes
 */


static bool rawsock_initialized = false;



/* ══════════════════════════════════════════
 *  Library Init / Shutdown
 * ══════════════════════════════════════════ 
 */

b579_result_t b579_rawsock_init(void)
{
    if (rawsock_initialized)
    {
        return B579_OK;
    }
    b579_result_t r = b579_platform_init();

    if (B579_IS_ERR(r))
    {
        return r;
    }
    rawsock_initialized = true;
    B579_DBG("rawsock initialized on %s", B579_OS_NAME);
    return B579_OK;
}

void b579_rawsock_shutdown(void) 
{
    if (!rawsock_initialized)
    {
        return;
    }
    rawsock_initialized = false;
    B579_DBG("rawsock shutdown");
}

/* ══════════════════════════════════════════
 *  Backend Selection (Factory)
 * ══════════════════════════════════════════ 
 */

 static const b579_backend_vtable_t *select_backend(b579_backend_t requested)
 {
        /* Explicit backend requested */
    if (requested != B579_BACKEND_AUTO) 
    {
        switch (requested) {
#ifdef HAVE_PFRING
            case B579_BACKEND_PFRING:
                return &b579_vtable_pfring;
#endif
#ifdef B579_OS_LINUX
            case B579_BACKEND_AFPACKET:
                return &b579_vtable_afpacket;
#endif
#if defined(B579_OS_MACOS) || defined(B579_OS_FREEBSD)
            case B579_BACKEND_BPF:
                return &b579_vtable_bpf;
#endif
#ifdef B579_OS_WINDOWS
            case B579_BACKEND_NPCAP:
                return &b579_vtable_npcap;
#endif
            case B579_BACKEND_PCAP:
                return &b579_vtable_pcap;
            default:
                b579_error_set(B579_ERR_INVAL,"unsupported backend: %d", requested);
                return NULL;
        }
    }

    /*
     * Auto-detect: try fastest first
     *
     * Priority order:
     *   1. PF_RING (kernel bypass, 10M+ pps)
     *   2. AF_PACKET (Linux native, 2M+ pps)
     *   3. BPF (macOS/FreeBSD native)
     *   4. Npcap (Windows native)
     *   5. libpcap (portable fallback)
     */

#ifdef HAVE_PFRING
    return &b579_vtable_pfring;
#endif

#ifdef B579_OS_LINUX
    return &b579_vtable_afpacket;
#endif

#if defined(B579_OS_MACOS) || defined(B579_OS_FREEBSD)
    return &b579_vtable_bpf;
#endif

#ifdef B579_OS_WINDOWS
    return &b579_vtable_npcap;
#endif
    /* Ultimate fallback */
    return &b579_vtable_pcap;
 }


/* ══════════════════════════════════════════
 *  Internal: Allocate adapter
 * ══════════════════════════════════════════ 
 */
b579_rawsock_t *b579_rawsock_alloc(void)
{
     b579_rawsock_t *sock = (b579_rawsock_t *)b579_malloc(sizeof(b579_rawsock_t));

     if (!sock)
     {
        return NULL;
     }
     sock->fd = -1;
     sock->handle = NULL;
     sock->vtable = NULL;
     /* Init atomic stats */
     b579_atomic_init(&sock->stat_pkts_sent, 0);
     b579_atomic_init(&sock->stat_pkts_recv, 0);
     b579_atomic_init(&sock->stat_bytes_sent, 0);
     b579_atomic_init(&sock->stat_bytes_recv, 0);
     b579_atomic_init(&sock->stat_errors_send, 0);
     b579_atomic_init(&sock->stat_errors_recv, 0);
     b579_atomic_init(&sock->stat_dropped, 0);
     sock->rate_last_time_ns = b579_timer_nanos();
     sock->rate_last_pkts_sent = 0;
     sock->rate_last_pkts_recv = 0;
     return sock;
}

/* ══════════════════════════════════════════
 *  Open / Close
 * ══════════════════════════════════════════ 
 */

b579_rawsock_t *b579_rawsock_open(const b579_rawsock_config_t *config) 
{
    if (!config) 
    {
        b579_error_set(B579_ERR_NULL, "config is NULL");
        return NULL;
    }

    if (!rawsock_initialized) 
    {
        b579_error_set(B579_ERR, "rawsock not initialized, call b579_rawsock_init()");
        return NULL;
    }

    /* Select backend */
    const b579_backend_vtable_t *vt = select_backend(config->backend);

    if (!vt)
    {
        return NULL;
    }
    /* Allocate adapter */
    b579_rawsock_t *sock = b579_rawsock_alloc();

    if (!sock)
    {
        return NULL;
    }
    /* Copy config */
    sock->vtable = vt;
    sock->config = *config;

    /* Resolve interface info if name provided */
    if (config->ifname && config->ifname[0]) 
    {
        b579_result_t r = b579_if_get(config->ifname, &sock->ifinfo);

        if (B579_IS_ERR(r)) 
        {
            B579_DBG("warning: could not get info for interface '%s'",config->ifname);
        }
    } else {
        /* Auto-detect interface */
        b579_result_t r = b579_if_find_default(&sock->ifinfo);

        if (B579_IS_ERR(r)) 
        {
            b579_error_set(B579_ERR, "no suitable network interface found");
            b579_free(sock, sizeof(*sock));
            return NULL;
        }
        /* Update config with discovered interface name */
        sock->config.ifname = sock->ifinfo.name;
    }

    /* Call backend open */
    b579_result_t r = vt->open(sock, &sock->config);

    if (B579_IS_ERR(r)) 
    {
        b579_free(sock, sizeof(*sock));
        return NULL;
    }
    B579_DBG("adapter opened: if=%s backend=%s sending=%d",sock->ifinfo.name, vt->name, config->is_sending);
    return sock;
}

void b579_rawsock_close(b579_rawsock_t *sock) 
{
    if (!sock)
    {
        return;
    }
    B579_DBG("closing adapter: if=%s backend=%s pkts_sent=%llu pkts_recv=%llu",sock->ifinfo.name,sock->vtable ? sock->vtable->name : "none",(unsigned long long)b579_atomic_load(&sock->stat_pkts_sent),(unsigned long long)b579_atomic_load(&sock->stat_pkts_recv));

    /* Call backend close */
    if (sock->vtable && sock->vtable->close) 
    {
        sock->vtable->close(sock);
    }
    b579_free(sock, sizeof(*sock));
}


/* ══════════════════════════════════════════
 *  Send / Receive — delegate through vtable
 * ══════════════════════════════════════════ 
 */

int b579_rawsock_send(b579_rawsock_t *sock,const uint8_t *frame,size_t length) {
    B579_CHECK_NULL(sock);
    B579_CHECK_NULL(frame);
    B579_CHECK(length >= 14, B579_ERR_INVAL); /* Minimum ethernet frame */
    int sent = sock->vtable->send(sock, frame, length);

    if (sent > 0) 
    {
        b579_rawsock_stat_sent(sock, (size_t)sent);
    } else {
        b579_rawsock_stat_send_err(sock);
    }
    return sent;
}

int b579_rawsock_send_batch(b579_rawsock_t *sock,const uint8_t **frames,const size_t *lengths,size_t count) 
{
    B579_CHECK_NULL(sock);
    B579_CHECK_NULL(frames);
    B579_CHECK_NULL(lengths);

    /*
     * TODO: Some backends support true batch sending
     * (sendmmsg on Linux, io_uring in the future).
     * For now, loop through individual sends.
     * The C-level loop is still faster than Rust→C FFI per packet.
     */
    int total = 0;

    for (size_t i = 0; i < count; i++) 
    {
        int r = b579_rawsock_send(sock, frames[i], lengths[i]);
        if (r > 0) total++;
    }
    return total;
}

int b579_rawsock_recv(b579_rawsock_t *sock,uint8_t *buf,size_t buf_size,int timeout_ms) 
{
    B579_CHECK_NULL(sock);
    B579_CHECK_NULL(buf);
    int received = sock->vtable->recv(sock, buf, buf_size, timeout_ms);

    if (received > 0) 
    {
        b579_rawsock_stat_recv(sock, (size_t)received);
    } else if (received < 0) {
        b579_rawsock_stat_recv_err(sock);
    }
    /* received == 0 means timeout — not an error */
    return received;
}


/* ══════════════════════════════════════════
 *  Adapter Info
 * ══════════════════════════════════════════ 
 */

b579_backend_t b579_rawsock_get_backend(const b579_rawsock_t *sock) 
{
    return sock ? sock->vtable->type : B579_BACKEND_AUTO;
}

const char *b579_rawsock_get_backend_name(const b579_rawsock_t *sock) 
{
    return sock ? sock->vtable->name : "none";
}

int b579_rawsock_get_fd(const b579_rawsock_t *sock) {

    if (!sock || !sock->vtable->get_fd)
    {
        return -1;
    }
    return sock->vtable->get_fd(sock);
}

b579_result_t b579_rawsock_get_ifinfo(const b579_rawsock_t *sock,b579_ifinfo_t *info) 
{
    B579_CHECK_NULL(sock);
    B579_CHECK_NULL(info);
    *info = sock->ifinfo;
    return B579_OK;
}


/* ══════════════════════════════════════════
 *  Filter — delegate to backend
 * ══════════════════════════════════════════ 
 */

b579_result_t b579_rawsock_set_filter(b579_rawsock_t *sock,const char *filter_expr) 
{
    B579_CHECK_NULL(sock);
    B579_CHECK_NULL(filter_expr);

    if (!sock->vtable->set_filter) 
    {
        b579_error_set(B579_ERR_NOSYS,"backend '%s' does not support filters",sock->vtable->name);
        return B579_ERR_NOSYS;
    }
    B579_DBG("setting filter: '%s'", filter_expr);
    return sock->vtable->set_filter(sock, filter_expr);
}


/* ══════════════════════════════════════════
 *  Interface Discovery — delegate to OS
 * ══════════════════════════════════════════ 
 */

b579_result_t b579_if_get(const char *ifname, b579_ifinfo_t *info) 
{
    B579_CHECK_NULL(ifname);
    B579_CHECK_NULL(info);
    memset(info, 0, sizeof(*info));
    return b579_if_get_os(ifname, info);
}

int b579_if_list(b579_ifinfo_t *list, size_t max_count) 
{
    if (!list || max_count == 0)
    {
        return B579_ERR_NULL;
    }
    memset(list, 0, max_count * sizeof(*list));
    return b579_if_list_os(list, max_count);
}

b579_result_t b579_if_find_default(b579_ifinfo_t *info) 
{
    B579_CHECK_NULL(info);

    b579_ifinfo_t ifs[32];
    int count = b579_if_list(ifs, B579_ARRAY_LEN(ifs));

    if (count <= 0) 
    {
        b579_error_set(B579_ERR, "no network interfaces found");
        return B579_ERR;
    }

    for (int i = 0; i < count; i++) 
    {
        if (!ifs[i].is_loopback && ifs[i].is_up && ifs[i].ipv4 != 0) 
        {
            *info = ifs[i];
            B579_DBG("default interface: %s (ip=%u.%u.%u.%u)",info->name,(info->ipv4 >> 24) & 0xFF,(info->ipv4 >> 16) & 0xFF,(info->ipv4 >>  8) & 0xFF,(info->ipv4) & 0xFF);
            return B579_OK;
        }
    }
    b579_error_set(B579_ERR, "no suitable default interface");
    return B579_ERR;
}


/* ══════════════════════════════════════════
 *  Routing — delegate to OS
 * ══════════════════════════════════════════ 
 */

b579_result_t b579_route_get(uint32_t dst_ip, b579_route_t *route) 
{
    B579_CHECK_NULL(route);
    memset(route, 0, sizeof(*route));
    return b579_route_get_os(dst_ip, route);
}

b579_result_t b579_route_get_default(b579_route_t *route) 
{
    B579_CHECK_NULL(route);
    /* Default route = route for 0.0.0.0 */
    return b579_route_get(0, route);
}

int b579_route_list(b579_route_t *list, size_t max_count) 
{
    if (!list || max_count == 0)
    {
        return B579_ERR_NULL;
    }
    memset(list, 0, max_count * sizeof(*list));
    return b579_route_list_os(list, max_count);
}


/* ══════════════════════════════════════════
 *  ARP — try cache first, then send request
 * ══════════════════════════════════════════ 
 */

b579_result_t b579_arp_resolve(b579_rawsock_t *sock,uint32_t target_ip,uint8_t target_mac[B579_MAC_LEN],int timeout_ms) 
{
    B579_CHECK_NULL(sock);
    B579_CHECK_NULL(target_mac);
    /* Try cache first — no network traffic */
    b579_result_t r = b579_arp_cache_lookup(target_ip, target_mac);

    if (B579_IS_OK(r)) 
    {
        B579_DBG("ARP cache hit for %u.%u.%u.%u",(target_ip >> 24) & 0xFF, (target_ip >> 16) & 0xFF,(target_ip >> 8) & 0xFF, (target_ip) & 0xFF);
        return B579_OK;
    }
    /* Cache miss — send ARP request */
    B579_DBG("ARP cache miss, sending request for %u.%u.%u.%u",(target_ip >> 24) & 0xFF, (target_ip >> 16) & 0xFF,(target_ip >> 8) & 0xFF, (target_ip) & 0xFF);
    return b579_arp_send_request(sock, target_ip, target_mac, timeout_ms);
}

b579_result_t b579_arp_cache_lookup(uint32_t target_ip,uint8_t  target_mac[B579_MAC_LEN]) 
{
    if (!target_mac)
    {
        return B579_ERR_NULL;
    }
    return b579_arp_cache_lookup_os(target_ip, target_mac);
}


/* ══════════════════════════════════════════
 *  Backend Availability
 * ══════════════════════════════════════════ 
 */

int b579_rawsock_backend_available(b579_backend_t backend) 
{
    switch (backend) {
        case B579_BACKEND_PCAP:
            return 1; /* Always available if we compiled */

#ifdef B579_OS_LINUX
        case B579_BACKEND_AFPACKET:
            return 1;
#endif

#if defined(B579_OS_MACOS) || defined(B579_OS_FREEBSD)
        case B579_BACKEND_BPF:
            return 1;
#endif

#ifdef B579_OS_WINDOWS
        case B579_BACKEND_NPCAP:
            return 1;
#endif

#ifdef HAVE_PFRING
        case B579_BACKEND_PFRING:
            return 1;
#endif
        default:
            return 0;
    }
}

static char available_backends_buf[256] = {0};

const char *b579_rawsock_available_backends(void) 
{
    if (available_backends_buf[0])
    {
        return available_backends_buf;
    }
    size_t pos = 0;
    const char *sep = "";

#ifdef B579_OS_LINUX
    pos += snprintf(available_backends_buf + pos,sizeof(available_backends_buf) - pos,"%sAF_PACKET", sep);
    sep = ", ";
#endif

#if defined(B579_OS_MACOS) || defined(B579_OS_FREEBSD)
    pos += snprintf(available_backends_buf + pos,sizeof(available_backends_buf) - pos,"%sBPF", sep);
    sep = ", ";
#endif

#ifdef B579_OS_WINDOWS
    pos += snprintf(available_backends_buf + pos,sizeof(available_backends_buf) - pos,"%sNpcap", sep);
    sep = ", ";
#endif

    pos += snprintf(available_backends_buf + pos,sizeof(available_backends_buf) - pos,"%slibpcap", sep);
    sep = ", ";

#ifdef HAVE_PFRING
    pos += snprintf(available_backends_buf + pos,sizeof(available_backends_buf) - pos,"%sPF_RING", sep);
#endif

    B579_UNUSED(sep);
    return available_backends_buf;
}





