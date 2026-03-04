
#ifdef B579_OS_LINUX

#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <net/ethernet.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <linux/filter.h>
#include <unistd.h>
#include <poll.h>
#include <fcntl.h>

#include "include/b579_rawsock_internal.h"

/*
 * B-579 Arwah — Linux AF_PACKET Backend
 *
 * Direct kernel raw socket — fastest option on Linux
 * without kernel bypass (PF_RING/DPDK).
 *
 * AF_PACKET + SOCK_RAW:
 *   - Send/receive raw Ethernet frames
 *   - Bypass TCP/IP stack entirely
 *   - Promiscuous mode for capturing
 *   - Zero-copy possible via PACKET_MMAP (future)
 *
 * Requires root (CAP_NET_RAW).
 */
static b579_result_t afpacket_open(b579_rawsock_t *sock,const b579_rawsock_config_t *config) 
{
    /* Create AF_PACKET raw socket */
    int fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));

    if (fd < 0) 
    {
        b579_error_set_errno("socket(AF_PACKET)");
        return B579_ERR_PERM;
    }
    /* Get interface index */
    int ifindex = if_nametoindex(config->ifname);

    if (ifindex == 0) 
    {
        b579_error_set_errno("if_nametoindex");
        close(fd);
        return B579_ERR_INVAL;
    }
    /* Bind to specific interface */
    struct sockaddr_ll sll;
    memset(&sll, 0, sizeof(sll));
    sll.sll_family   = AF_PACKET;
    sll.sll_protocol = htons(ETH_P_ALL);
    sll.sll_ifindex  = ifindex;

    if (bind(fd, (struct sockaddr *)&sll, sizeof(sll)) < 0) 
    {
        b579_error_set_errno("bind(AF_PACKET)");
        close(fd);
        return B579_ERR;
    }

    /* Set promiscuous mode if requested */
    if (config->promiscuous) 
    {
        struct packet_mreq mreq;
        memset(&mreq, 0, sizeof(mreq));
        mreq.mr_ifindex = ifindex;
        mreq.mr_type    = PACKET_MR_PROMISC;
        setsockopt(fd, SOL_PACKET, PACKET_ADD_MEMBERSHIP,&mreq, sizeof(mreq));
    }

    /* Increase socket buffers */
    if (config->send_buf_size > 0) 
    {
        setsockopt(fd, SOL_SOCKET, SO_SNDBUF,&config->send_buf_size,sizeof(config->send_buf_size));
    }

    if (config->recv_buf_size > 0) 
    {
        setsockopt(fd, SOL_SOCKET, SO_RCVBUF,&config->recv_buf_size,sizeof(config->recv_buf_size));
    }

    /* Non-blocking mode for receiver */
    if (!config->is_sending) 
    {
        int flags = fcntl(fd, F_GETFL, 0);
        fcntl(fd, F_SETFL, flags | O_NONBLOCK);
    }
    sock->fd = fd;
    return B579_OK;
}


static void afpacket_close(b579_rawsock_t *sock) 
{
    if (sock->fd >= 0) 
    {
        close(sock->fd);
        sock->fd = -1;
    }
}

static int afpacket_send(b579_rawsock_t *sock,const uint8_t  *frame,size_t length) 
{
    struct sockaddr_ll dst;
    memset(&dst, 0, sizeof(dst));
    dst.sll_family  = AF_PACKET;
    dst.sll_ifindex = sock->ifinfo.index;
    dst.sll_halen   = B579_MAC_LEN;
    /* Destination MAC from ethernet header */
    memcpy(dst.sll_addr, frame, B579_MAC_LEN);
    ssize_t sent = sendto(sock->fd, frame, length, 0,(struct sockaddr *)&dst, sizeof(dst));
    return (int)sent;
}

static int afpacket_recv(b579_rawsock_t *sock,uint8_t *buf,size_t buf_size,int timeout_ms) 
{
    /* Poll with timeout */
    struct pollfd pfd = {
        .fd      = sock->fd,
        .events  = POLLIN,
        .revents = 0,
    };
    int ret = poll(&pfd, 1, timeout_ms);

    if (ret <= 0)
    {
        return ret; /* 0=timeout, -1=error */
    }

    if (!(pfd.revents & POLLIN))
    {
        return 0;
    }
    ssize_t received = recv(sock->fd, buf, buf_size, 0);
    return (int)received;
}

/* ── Filter ── */

static b579_result_t afpacket_set_filter(b579_rawsock_t *sock,const char *filter_expr) 
{
    /*
     * AF_PACKET supports BPF filters via SO_ATTACH_FILTER.
     * We need to compile the filter expression to BPF bytecode.
     *
     * Use libpcap's pcap_compile() for compilation only,
     * then apply the compiled filter to our AF_PACKET socket.
     * This is a common pattern — even tools that don't use
     * libpcap for capture still use it for filter compilation.
     */
    B579_UNUSED(sock);
    B579_UNUSED(filter_expr);

    /*
     * TODO: Implement BPF filter compilation
     * Options:
     *   1. Link against libpcap just for pcap_compile()
     *   2. Write our own mini BPF compiler
     *   3. Use hardcoded BPF programs for common filters
     *
     * For now, return NOSYS and rely on userspace filtering.
     */
    return B579_ERR_NOSYS;
}

/* ── Get FD ── */

static int afpacket_get_fd(const b579_rawsock_t *sock) 
{
    return sock->fd;
}

/* ── Export vtable ── */

const b579_backend_vtable_t b579_vtable_afpacket = {
    .name = "AF_PACKET",
    .type = B579_BACKEND_AFPACKET,
    .open = afpacket_open,
    .close = afpacket_close,
    .send = afpacket_send,
    .recv = afpacket_recv,
    .set_filter = afpacket_set_filter,
    .get_fd = afpacket_get_fd,
};

#endif /* B579_OS_LINUX */






















