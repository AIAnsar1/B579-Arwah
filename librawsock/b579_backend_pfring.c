#ifdef HAVE_PFRING

#include <pfring.h>

#include "include/b579_rawsock_internal.h"

/* ── Open ── */

static b579_result_t pfring_open(b579_rawsock_t *sock,const b579_rawsock_config_t *config) 
{
    /*
     * PF_RING flags:
     *   PF_RING_PROMISC     — promiscuous mode
     *   PF_RING_TIMESTAMP   — hardware timestamps
     *   PF_RING_REENTRANT   — thread-safe (adds overhead)
     *   PF_RING_LONG_HEADER — capture full headers
     */
    uint32_t flags = PF_RING_LONG_HEADER;

    if (config->promiscuous) 
    {
        flags |= PF_RING_PROMISC;
    }
    pfring *ring = pfring_open(config->ifname,config->snaplen > 0 ? config->snaplen : 65535,flags);

    if (!ring) 
    {
        b579_error_set(B579_ERR, "pfring_open(%s) failed — is PF_RING kernel module loaded?",config->ifname);
        return B579_ERR;
    }

    /* Set ring buffer size */
    if (config->recv_buf_size > 0) 
    {
        /* PF_RING uses slots, not byte buffer */
        /* Approximate: each slot ~2KB */
        uint32_t num_slots = config->recv_buf_size / 2048;

        if (num_slots < 4096)
        {
            num_slots = 4096;
        }
        /* Ring size is set at open time, can't change after */
    }

    /* Enable ring */
    if (pfring_enable_ring(ring) != 0) 
    {
        b579_error_set(B579_ERR, "pfring_enable_ring failed");
        pfring_close(ring);
        return B579_ERR;
    }
    /* Set socket send mode */
    pfring_set_socket_mode(ring,config->is_sending ? send_only_mode : recv_only_mode);
    sock->handle = ring;
    sock->fd = pfring_get_selectable_fd(ring);
    B579_DBG("PF_RING opened: %s, version=%s",config->ifname, pfring_version());
    return B579_OK;
}

/* ── Close ── */

static void pfring_close_backend(b579_rawsock_t *sock) 
{
    if (sock->handle) 
    {
        pfring_close((pfring *)sock->handle);
        sock->handle = NULL;
        sock->fd     = -1;
    }
}

/* ── Send ── */

static int pfring_send_backend(b579_rawsock_t *sock,const uint8_t *frame,size_t length) 
{
    pfring *ring = (pfring *)sock->handle;

    /*
     * pfring_send arguments:
     *   pkt      — packet data
     *   pkt_len  — packet length
     *   flush    — 1 = flush TX ring immediately
     *
     * For maximum throughput, flush=0 and call pfring_flush_tx_packets()
     * periodically. For simplicity, we flush every packet.
     */
    int ret = pfring_send(ring, (char *)frame, (unsigned int)length, 1);

    /* pfring_send returns the packet length on success, negative on error */
    return ret;
}

/* ── Receive ── */

static int pfring_recv_backend(b579_rawsock_t *sock,uint8_t *buf,size_t buf_size,int timeout_ms) 
{
    pfring *ring = (pfring *)sock->handle;
    struct pfring_pkthdr hdr;
    uint8_t *pkt_data = NULL;

    /*
     * pfring_recv:
     *   buffer       — pointer to receive buffer (or NULL for zero-copy)
     *   buffer_len   — buffer size
     *   hdr          — packet metadata
     *   wait_for_pkt — 1 = block until packet arrives
     *
     * Returns: 1 = packet received, 0 = no packet (timeout)
     */

    /* Set poll timeout */
    pfring_set_poll_duration(ring, timeout_ms);
    int ret = pfring_recv(ring, &pkt_data, 0, &hdr, 1);

    if (ret > 0 && pkt_data && hdr.caplen > 0) 
    {
        size_t copy_len = B579_MIN(hdr.caplen, buf_size);
        memcpy(buf, pkt_data, copy_len);

        /* Track kernel drops */
        pfring_stat stats;

        if (pfring_stats(ring, &stats) == 0) 
        {
            b579_atomic_store(&sock->stat_dropped, stats.drop);
        }
        return (int)copy_len;
    }
    return 0; /* Timeout or no packet */
}

/* ── Filter ── */

static b579_result_t pfring_set_filter_backend(b579_rawsock_t *sock,const char *filter_expr) 
{
    pfring *ring = (pfring *)sock->handle;

    /* PF_RING supports BPF filter syntax */
    if (pfring_set_bpf_filter(ring, (char *)filter_expr) != 0) 
    {
        b579_error_set(B579_ERR_INVAL,"pfring_set_bpf_filter('%s') failed",filter_expr);
        return B579_ERR_INVAL;
    }
    return B579_OK;
}

/* ── Get FD ── */

static int pfring_get_fd(const b579_rawsock_t *sock) 
{
    return sock->fd;
}

/* ── Export vtable ── */

const b579_backend_vtable_t b579_vtable_pfring = {
    .name = "PF_RING",
    .type = B579_BACKEND_PFRING,
    .open = pfring_open,
    .close = pfring_close_backend,
    .send = pfring_send_backend,
    .recv = pfring_recv_backend,
    .set_filter = pfring_set_filter_backend,
    .get_fd = pfring_get_fd,
};

#endif /* HAVE_PFRING */
