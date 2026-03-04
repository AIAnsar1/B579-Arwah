#if defined(B579_OS_MACOS) || defined(B579_OS_FREEBSD)

#include <sys/ioctl.h>
#include <net/bpf.h>
#include <net/if.h>
#include <fcntl.h>
#include <unistd.h>

#include "include/b579_rawsock_internal.h"

/*
* B-579 Arwah — BPF Backend (macOS / FreeBSD)
*
* Berkeley Packet Filter — native raw packet access
* on BSD-derived systems.
*
* Opens /dev/bpf0..N, binds to interface, sends/receives
* raw ethernet frames.
*/

static b579_result_t bpf_open(b579_rawsock_t *sock,const b579_rawsock_config_t *config) {
    char bpf_dev[32];
    int fd = -1;

    /* Try /dev/bpf0 through /dev/bpf255 until one opens */
    for (int i = 0; i < 256; i++) 
    {
        snprintf(bpf_dev, sizeof(bpf_dev), "/dev/bpf%d", i);
        fd = open(bpf_dev, O_RDWR);
        if (fd >= 0)
        {
            break;
        }
    }

    if (fd < 0) 
    {
        b579_error_set_errno("open(/dev/bpf*)");
        return B579_ERR_PERM;
    }
    /* Bind to interface */
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, config->ifname,sizeof(ifr.ifr_name) - 1);

    if (ioctl(fd, BIOCSETIF, &ifr) < 0) 
    {
        b579_error_set_errno("ioctl(BIOCSETIF)");
        close(fd);
        return B579_ERR;
    }

    /* Enable immediate mode */
    int enable = 1;
    ioctl(fd, BIOCIMMEDIATE, &enable);
    /* Header complete — we provide full ethernet header */
    ioctl(fd, BIOCSHDRCMPLT, &enable);

    /* Promiscuous mode */
    if (config->promiscuous) 
    {
        ioctl(fd, BIOCPROMISC, NULL);
    }

    /* Set buffer size */
    if (config->recv_buf_size > 0) 
    {
        int bufsize = config->recv_buf_size;
        ioctl(fd, BIOCSBLEN, &bufsize);
    }
    sock->fd = fd;
    return B579_OK;
}

static void bpf_close(b579_rawsock_t *sock) 
{
    if (sock->fd >= 0) 
    {
        close(sock->fd);
        sock->fd = -1;
    }
}

static int bpf_send(b579_rawsock_t *sock,const uint8_t  *frame,size_t length) 
{
    ssize_t sent = write(sock->fd, frame, length);
    return (int)sent;
}

static int bpf_recv(b579_rawsock_t *sock,uint8_t *buf,size_t buf_size,int timeout_ms) 
{
    /* BPF read returns frames with BPF header prepended */
    struct timeval tv;
    tv.tv_sec  = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    ioctl(sock->fd, BIOCSRTIMEOUT, &tv);
    uint8_t raw_buf[65536];
    ssize_t n = read(sock->fd, raw_buf, sizeof(raw_buf));

    if (n <= 0)
    {
        return (int)n;
    }
    /* Parse BPF header to get actual packet */
    struct bpf_hdr *bh = (struct bpf_hdr *)raw_buf;
    uint8_t *pkt = raw_buf + bh->bh_hdrlen;
    size_t pkt_len = bh->bh_caplen;
    size_t copy_len = B579_MIN(pkt_len, buf_size);
    memcpy(buf, pkt, copy_len);
    return (int)copy_len;
}

static b579_result_t bpf_set_filter(b579_rawsock_t *sock,const char *filter_expr) 
{
    B579_UNUSED(sock);
    B579_UNUSED(filter_expr);
    /* TODO: compile BPF filter and apply via BIOCSETF */
    return B579_ERR_NOSYS;
}

static int bpf_get_fd(const b579_rawsock_t *sock) 
{
    return sock->fd;
}

const b579_backend_vtable_t b579_vtable_bpf = {
    .name = "BPF",
    .type = B579_BACKEND_BPF,
    .open = bpf_open,
    .close = bpf_close,
    .send = bpf_send,
    .recv = bpf_recv,
    .set_filter = bpf_set_filter,
    .get_fd = bpf_get_fd,
};

#endif /* B579_OS_MACOS || B579_OS_FREEBSD */























