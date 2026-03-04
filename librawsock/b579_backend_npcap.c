#ifdef B579_OS_WINDOWS

#include "rawsock_internal.h"

#ifndef WIN32_LEAN_AND_MEAN
    #define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <pcap/pcap.h>

/*
* B-579 Arwah — Npcap Backend (Windows)
*
* Uses Npcap (successor to WinPcap) for raw packet I/O.
* Npcap provides libpcap-compatible API on Windows.
*
* Note: This backend uses the same pcap API as backend_pcap.c
* but with Windows-specific initialization and device naming.
*/


/* Windows interface names are like:
 * \Device\NPF_{GUID}
 * We need to translate user-friendly names */

static b579_result_t npcap_open(b579_rawsock_t *sock,const b579_rawsock_config_t *config) 
{
    char errbuf[PCAP_ERRBUF_SIZE];
    /* On Windows, pcap_open_live handles Npcap devices */
    pcap_t *pcap = pcap_open_live(config->ifname,config->snaplen > 0 ? config->snaplen : 65535,config->promiscuous ? 1 : 0,config->timeout_ms > 0 ? config->timeout_ms : 1,errbuf);

    if (!pcap) 
    {
        b579_error_set(B579_ERR, "npcap open: %s", errbuf);
        return B579_ERR;
    }
    sock->handle = pcap;
    sock->fd = -1; /* Windows doesn't use fd */
    return B579_OK;
}

static void npcap_close(b579_rawsock_t *sock) 
{
    if (sock->handle) 
    {
        pcap_close((pcap_t *)sock->handle);
        sock->handle = NULL;
    }
}

static int npcap_send(b579_rawsock_t *sock,const uint8_t *frame,size_t length) 
{
    return pcap_inject((pcap_t *)sock->handle, frame, length);
}

static int npcap_recv(b579_rawsock_t *sock,uint8_t *buf,size_t buf_size,int timeout_ms) 
{
    B579_UNUSED(timeout_ms);
    pcap_t *pcap = (pcap_t *)sock->handle;
    struct pcap_pkthdr *header;
    const uint8_t *data;
    int ret = pcap_next_ex(pcap, &header, &data);

    if (ret == 1 && header->caplen > 0) 
    {
        size_t copy_len = B579_MIN(header->caplen, buf_size);
        memcpy(buf, data, copy_len);
        return (int)copy_len;
    }
    return (ret == 0) ? 0 : -1;
}

static b579_result_t npcap_set_filter(b579_rawsock_t *sock,const char *filter_expr) 
{
    pcap_t *pcap = (pcap_t *)sock->handle;
    struct bpf_program fp;

    if (pcap_compile(pcap, &fp, filter_expr, 1, PCAP_NETMASK_UNKNOWN) < 0) 
    {
        b579_error_set(B579_ERR_INVAL, "pcap_compile: %s",pcap_geterr(pcap));
        return B579_ERR_INVAL;
    }

    if (pcap_setfilter(pcap, &fp) < 0) 
    {
        pcap_freecode(&fp);
        return B579_ERR;
    }
    pcap_freecode(&fp);
    return B579_OK;
}

static int npcap_get_fd(const b579_rawsock_t *sock) 
{
    B579_UNUSED(sock);
    return -1; /* Windows uses events, not fds */
}

const b579_backend_vtable_t b579_vtable_npcap = {
    .name = "Npcap",
    .type = B579_BACKEND_NPCAP,
    .open = npcap_open,
    .close = npcap_close,
    .send = npcap_send,
    .recv = npcap_recv,
    .set_filter = npcap_set_filter,
    .get_fd = npcap_get_fd,
};

#endif /* B579_OS_WINDOWS */



















