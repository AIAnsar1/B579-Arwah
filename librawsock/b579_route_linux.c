#ifdef B579_OS_LINUX

#include <stdio.h>
#include <arpa/inet.h>

#include "include/b579_rawsock_internal.h"


b579_result_t b579_route_get_os(uint32_t dst_ip, b579_route_t *route) 
{
    FILE *fp = fopen("/proc/net/route", "r");

    if (!fp) 
    {
        b579_error_set_errno("fopen(/proc/net/route)");
        return B579_ERR;
    }
    /* Skip header line */
    char line[512];

    if (!fgets(line, sizeof(line), fp)) 
    {
        fclose(fp);
        return B579_ERR;
    }
    uint32_t = 0;
    int found = 0;

    while (fgets(line, sizeof(line), fp)) 
    {
        char ifname[64];
        uint32_t dest, gateway, mask;
        unsigned flags;
        int metric;
        int n = sscanf(line, "%63s %X %X %u %*d %*d %d %X",ifname, &dest, &gateway, &flags,&metric, &mask);
        if (n < 6)
        {
            continue;
        }
        /* Route must be UP (flag 0x01) and GATEWAY (flag 0x02) */
        if (!(flags & 0x01))
        {
            continue;
        }
        /* Check if route matches destination */
        uint32_t dst_host = b579_hton32(dst_ip);

        if ((dst_host & mask) == dest) 
        {
            /*
             * Longest prefix match: use the route with
             * the most specific (largest) netmask.
             */
            if (mask >= best_mask) 
            {
                best_mask = mask;
                route->dst_ip = ntohl(dest);
                route->netmask = ntohl(mask);
                route->gateway_ip = ntohl(gateway);
                route->metric = metric;
                route->is_default = (dest == 0 && mask == 0) ? 1 : 0;
                strncpy(route->ifname, ifname,B579_IFNAME_MAX - 1);
                found = 1;
            }
        }
    }
    fclose(fp);

    if (!found) 
    {
        b579_error_set(B579_ERR, "no route to %u.%u.%u.%u",(dst_ip >> 24) & 0xFF,(dst_ip >> 16) & 0xFF,(dst_ip >>  8) & 0xFF,(dst_ip) & 0xFF);
        return B579_ERR;
    }
    return B579_OK;
}

int b579_route_list_os(b579_route_t *list, size_t max_count) 
{
    FILE *fp = fopen("/proc/net/route", "r");

    if (!fp)
    {
        return B579_ERR;
    }
    char line[512];
    /* Skip header */
    if (!fgets(line, sizeof(line), fp)) 
    {
        fclose(fp);
        return B579_ERR;
    }
    int count = 0;

    while (fgets(line, sizeof(line), fp) && (size_t)count < max_count) 
    {
        char ifname[64];
        uint32_t dest, gateway, mask;
        unsigned flags;
        int metric;
        int n = sscanf(line, "%63s %X %X %u %*d %*d %d %X", ifname, &dest, &gateway, &flags,&metric, &mask);

        if (n < 6)
        {
            continue;
        }

        if (!(flags & 0x01))
        {
             continue;
        }
        b579_route_t *r = &list[count];
        r->dst_ip     = ntohl(dest);
        r->netmask    = ntohl(mask);
        r->gateway_ip = ntohl(gateway);
        r->metric     = metric;
        r->is_default = (dest == 0 && mask == 0) ? 1 : 0;
        strncpy(r->ifname, ifname, B579_IFNAME_MAX - 1);
        count++;
    }
    fclose(fp);
    return count;
}

#endif /* B579_OS_LINUX */