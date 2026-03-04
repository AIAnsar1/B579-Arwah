#include <pcap/pcap.h>

#include "include/b579_rawsock_internal.h"

/*
 * B-579 Arwah — libpcap Backend
 *
 * The portable fallback. Works on Linux, macOS, Windows.
 * Slower than native backends but guaranteed to work.
 *
 * Links against system libpcap (apt install libpcap-dev).
 */

static b579_result_t pcap_open(b579_rawsock_t *sock,const b579_rawsock_config_t *config) 
{
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *pcap = pcap_open_live(config->ifname,config->snaplen > 0 ? config->snaplen : 65535,config->promiscuous ? 1 : 0,config->timeout_ms > 0 ? config->timeout_ms : 1,errbuf);

    if (!pcap) 
    {
        b579_error_set(B579_ERR, "pcap_open_live: %s", errbuf);
        return B579_ERR;
    }
    /* Set immediate mode — don't buffer packets */
    pcap_set_immediate_mode(pcap, 1);

    /* Set buffer sizes if specified */
    if (config->recv_buf_size > 0) 
    {
        pcap_set_buffer_size(pcap, config->recv_buf_size);
    }
    sock->handle = pcap;
    sock->fd = pcap_fileno(pcap);
    return B579_OK;
}

/* ── Close ── */

static void pcap_close_backend(b579_rawsock_t *sock) 
{
    if (sock->handle) 
    {
        pcap_close((pcap_t *)sock->handle);
        sock->handle = NULL;
        sock->fd = -1;
    }
}

/* ── Send ── */

static int pcap_send(b579_rawsock_t *sock,const uint8_t *frame,size_t length) 
{
    pcap_t *pcap = (pcap_t *)sock->handle;
    int ret = pcap_inject(pcap, frame, length);

    if (ret < 0) 
    {
        b579_error_set(B579_ERR_IO, "pcap_inject: %s",pcap_geterr(pcap));
    }
    return ret;
}

/* ── Receive ── */

static int pcap_recv(b579_rawsock_t *sock,uint8_t *buf,size_t buf_size,int timeout_ms) 
{
    pcap_t *pcap = (pcap_t *)sock->handle;
    B579_UNUSED(timeout_ms); /* Handled by pcap_open_live timeout */
    struct pcap_pkthdr *header;
    const uint8_t *data;
    int ret = pcap_next_ex(pcap, &header, &data);

    if (ret == 1 && header->caplen > 0) 
    {
        size_t copy_len = B579_MIN(header->caplen, buf_size);
        memcpy(buf, data, copy_len);
        return (int)copy_len;
    }

    if (ret == 0)  
    {
        return 0;   /* Timeout */
    }

    if (ret == -2) 
    {
        return 0;   /* EOF (reading from file) */
    }
    /* Error */
    b579_error_set(B579_ERR_IO, "pcap_next_ex: %s", pcap_geterr(pcap));
    return -1;
}

/* ── Filter ── */

static b579_result_t pcap_set_filter(b579_rawsock_t *sock,const char *filter_expr) 
{
    pcap_t *pcap = (pcap_t *)sock->handle;
    struct bpf_program fp;

    /* Compile filter expression to BPF bytecode */
    if (pcap_compile(pcap, &fp, filter_expr, 1, PCAP_NETMASK_UNKNOWN) < 0) 
    {
        b579_error_set(B579_ERR_INVAL, "pcap_compile('%s'): %s",filter_expr, pcap_geterr(pcap));
        return B579_ERR_INVAL;
    }

    /* Apply compiled filter */
    if (pcap_setfilter(pcap, &fp) < 0) 
    {
        b579_error_set(B579_ERR, "pcap_setfilter: %s",pcap_geterr(pcap));
        pcap_freecode(&fp);
        return B579_ERR;
    }
    pcap_freecode(&fp);
    return B579_OK;
}

/* ── Get FD ── */

static int pcap_get_fd(const b579_rawsock_t *sock) 
{
    return sock->fd;
}

/* ── Export vtable ── */

const b579_backend_vtable_t b579_vtable_pcap = {
    .name = "libpcap",
    .type = B579_BACKEND_PCAP,
    .open = pcap_open,
    .close = pcap_close_backend,
    .send = pcap_send,
    .recv = pcap_recv,
    .set_filter = pcap_set_filter,
    .get_fd = pcap_get_fd,
};




















