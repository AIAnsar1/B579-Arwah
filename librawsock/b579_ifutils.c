#include <stdio.h>


#include "include/b579_rawsock_internal.h"


/* ══════════════════════════════════════════
 *  Format MAC address as string
 * ══════════════════════════════════════════ 
 */

void b579_if_mac_to_str(const uint8_t mac[B579_MAC_LEN],char *buf,size_t buf_size) 
{
    if (!mac || !buf || buf_size < 18)
    {
        return;
    }
    snprintf(buf, buf_size, "%02x:%02x:%02x:%02x:%02x:%02x",mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

/* ══════════════════════════════════════════
 *  Format IPv4 address as string
 * ══════════════════════════════════════════ 
 */

void b579_if_ip_to_str(uint32_t ip,char *buf,size_t buf_size) 
{
    if (!buf || buf_size < 16)
    {
        return;
    }
    snprintf(buf, buf_size, "%u.%u.%u.%u",(ip >> 24) & 0xFF,(ip >> 16) & 0xFF,(ip >> 8) & 0xFF,(ip) & 0xFF);
}

/* ══════════════════════════════════════════
 *  Parse IPv4 string to uint32
 * ══════════════════════════════════════════ 
 */

b579_result_t b579_if_str_to_ip(const char *str, uint32_t *ip) 
{
    B579_CHECK_NULL(str);
    B579_CHECK_NULL(ip);
    unsigned a, b, c, d;

    if (sscanf(str, "%u.%u.%u.%u", &a, &b, &c, &d) != 4) 
    {
        return B579_ERR_INVAL;
    }

    if (a > 255 || b > 255 || c > 255 || d > 255) 
    {
        return B579_ERR_RANGE;
    }
    *ip = (a << 24) | (b << 16) | (c << 8) | d;
    return B579_OK;
}

/* ══════════════════════════════════════════
 *  Check if IP is on same subnet
 * ══════════════════════════════════════════ 
 */

int b579_if_same_subnet(uint32_t ip_a,uint32_t ip_b,uint32_t netmask) 
{
    return (ip_a & netmask) == (ip_b & netmask);
}

/* ══════════════════════════════════════════
 *  Print interface info (debug helper)
 * ══════════════════════════════════════════ 
 */


void b579_if_print(const b579_ifinfo_t *info) 
{
    if (!info)
    {
        return;
    }
    char ip_str[16];
    char mac_str[18];
    b579_if_ip_to_str(info->ipv4, ip_str, sizeof(ip_str));
    b579_if_mac_to_str(info->mac, mac_str, sizeof(mac_str));
    fprintf(stderr,"%-16s ip=%-15s mac=%s mtu=%u %s%s%s %llu Mbps\n",info->name,ip_str,mac_str,info->mtu,info->is_up ? "UP " : "DOWN ",info->is_running ? "RUNNING " : "",info->is_loopback ? "LOOPBACK " : "",(unsigned long long)info->speed_mbps);
}







