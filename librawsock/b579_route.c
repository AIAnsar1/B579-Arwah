#include <stdio.h>



#include "include/b579_rawsock_internal.h"




b579_result_t b579_route_resolve_nexthop(const b579_ifinfo_t *ifinfo,uint32_t dst_ip,uint32_t *nexthop_ip) 
{
    B579_CHECK_NULL(ifinfo);
    B579_CHECK_NULL(nexthop_ip);

    /* Same subnet? Send directly to target */
    if (b579_if_same_subnet(ifinfo->ipv4, dst_ip, ifinfo->netmask)) 
    {
        *nexthop_ip = dst_ip;
        B579_DBG("route: %u.%u.%u.%u is on same subnet, direct",(dst_ip >> 24) & 0xFF, (dst_ip >> 16) & 0xFF,(dst_ip >> 8) & 0xFF, (dst_ip) & 0xFF);
        return B579_OK;
    }
    /* Different subnet — need gateway */
    b579_route_t route;
    b579_result_t r = b579_route_get_os(dst_ip, &route);

    if (B579_IS_ERR(r)) 
    {
        /* Try default route */
        r = b579_route_get_os(0, &route);

        if (B579_IS_ERR(r)) 
        {
            b579_error_set(B579_ERR, "no route to host and no default gateway");
            return B579_ERR;
        }
    }
    *nexthop_ip = route.gateway_ip;
    B579_DBG("route: %u.%u.%u.%u via gateway %u.%u.%u.%u",(dst_ip >> 24) & 0xFF, (dst_ip >> 16) & 0xFF,(dst_ip >>  8) & 0xFF, (dst_ip) & 0xFF,(route.gateway_ip >> 24) & 0xFF,(route.gateway_ip >> 16) & 0xFF,(route.gateway_ip >>  8) & 0xFF,(route.gateway_ip) & 0xFF);
    return B579_OK;
}

/* ══════════════════════════════════════════
 *  Full resolution: destination IP → MAC address to use
 *
 *  This is the complete workflow for scanning:
 *    1. Is target on our subnet?
 *       Yes → ARP resolve target directly
 *       No  → find gateway, ARP resolve gateway
 *    2. Return the MAC to put in ethernet dst field
 * ══════════════════════════════════════════ */

b579_result_t b579_route_resolve_dst_mac(b579_rawsock_t *sock,uint32_t dst_ip,uint8_t dst_mac[B579_MAC_LEN],int timeout_ms) 
{
    B579_CHECK_NULL(sock);
    B579_CHECK_NULL(dst_mac);
    /* Step 1: find nexthop IP */
    uint32_t nexthop;
    b579_result_t r = b579_route_resolve_nexthop(&sock->ifinfo,dst_ip, &nexthop);

    if (B579_IS_ERR(r))
    {
        return r;
    }
    /* Step 2: ARP resolve nexthop to MAC */
    return b579_arp_resolve(sock, nexthop, dst_mac, timeout_ms);
}

/* ══════════════════════════════════════════
 *  Print route (debug helper)
 * ══════════════════════════════════════════ 
 */

void b579_route_print(const b579_route_t *route) 
{
    if (!route)
    {
        return;
    }
    char dst_str[16], gw_str[16], mask_str[16];
    b579_if_ip_to_str(route->dst_ip,     dst_str,  sizeof(dst_str));
    b579_if_ip_to_str(route->gateway_ip, gw_str,   sizeof(gw_str));
    b579_if_ip_to_str(route->netmask,    mask_str, sizeof(mask_str));
    fprintf(stderr, "  %-15s  mask=%-15s  gw=%-15s  dev=%-8s  metric=%d%s\n",dst_str, mask_str, gw_str, route->ifname,route->metric,route->is_default ? " [DEFAULT]" : "");
}










