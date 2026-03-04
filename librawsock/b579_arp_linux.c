#ifdef B579_OS_LINUX

#include <stdio.h>
#include <arpa/inet.h>

#include "include/b579_rawsock_internal.h"

/*
* B-579 Arwah — Linux ARP Cache Lookup
*
* Reads /proc/net/arp for cached MAC addresses.
* Much faster than sending ARP request — no network wait.
*/

b579_result_t b579_arp_cache_lookup_os(uint32_t target_ip,uint8_t  target_mac[B579_MAC_LEN]) 
{
    FILE *fp = fopen("/proc/net/arp", "r");

    if (!fp) 
    {
        b579_error_set_errno("fopen(/proc/net/arp)");
        return B579_ERR;
    }
    /* Skip header: "IP address  HW type  Flags  HW address  Mask  Device" */
    char line[256];

    if (!fgets(line, sizeof(line), fp)) 
    {
        fclose(fp);
        return B579_ERR;
    }
    /* Convert target IP to string for comparison */
    char target_str[INET_ADDRSTRLEN];
    uint32_t target_net = htonl(target_ip);
    inet_ntop(AF_INET, &target_net, target_str, sizeof(target_str));

    while (fgets(line, sizeof(line), fp)) 
    {
        char ip_str[64];
        char mac_str[32];
        unsigned hw_type, flags;
        int n = sscanf(line, "%63s 0x%x 0x%x %31s",ip_str, &hw_type, &flags, mac_str);

        if (n < 4)
        {
            continue;
        }

        /* Check if IP matches */
        if (strcmp(ip_str, target_str) != 0)
        {
            continue;
        }

        /* Flags: 0x02 = complete entry, 0x00 = incomplete */
        if (!(flags & 0x02))
        {
            continue;
        }
        /* Parse MAC string "aa:bb:cc:dd:ee:ff" */
        unsigned int m[6];

        if (sscanf(mac_str, "%x:%x:%x:%x:%x:%x",&m[0], &m[1], &m[2], &m[3], &m[4], &m[5]) == 6) 
        {
            for (int i = 0; i < 6; i++) 
            {
                target_mac[i] = (uint8_t)m[i];
            }
            fclose(fp);
            return B579_OK;
        }
    }
    fclose(fp);
    return B579_ERR; /* Not found in cache */
}

#endif /* B579_OS_LINUX */














