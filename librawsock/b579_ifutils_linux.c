#ifdef B579_OS_LINUX

#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <stdio.h>

#include "include/b579_rawsock_internal.h"


/*
* B-579 Arwah — Linux Interface Utilities
*
* Uses ioctl() and /sys/class/net/ for interface info.
* ioctl is the traditional POSIX way.
* /sys/class/net gives link speed.
*/


b579_result_t b579_if_get_os(const char *ifname, b579_ifinfo_t *info) 
{
    int fd = socket(AF_INET, SOCK_DGRAM, 0);

    if (fd < 0) 
    {
        b579_error_set_errno("socket(AF_INET)");
        return B579_ERR;
    }
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);
    strncpy(info->name, ifname, B579_IFNAME_MAX - 1);

    /* MAC address */
    if (ioctl(fd, SIOCGIFHWADDR, &ifr) == 0) 
    {
        memcpy(info->mac, ifr.ifr_hwaddr.sa_data, B579_MAC_LEN);
    }

    /* IPv4 address */
    if (ioctl(fd, SIOCGIFADDR, &ifr) == 0) 
    {
        struct sockaddr_in *addr = (struct sockaddr_in *)&ifr.ifr_addr;
        info->ipv4 = ntohl(addr->sin_addr.s_addr);
    }

    /* Netmask */
    if (ioctl(fd, SIOCGIFNETMASK, &ifr) == 0) 
    {
        struct sockaddr_in *mask = (struct sockaddr_in *)&ifr.ifr_netmask;
        info->netmask = ntohl(mask->sin_addr.s_addr);
    }

    /* MTU */
    if (ioctl(fd, SIOCGIFMTU, &ifr) == 0) 
    {
        info->mtu = (uint32_t)ifr.ifr_mtu;
    }

    /* Flags (UP, LOOPBACK, RUNNING) */
    if (ioctl(fd, SIOCGIFFLAGS, &ifr) == 0) 
    {
        info->is_up = (ifr.ifr_flags & IFF_UP) ? 1 : 0;
        info->is_loopback = (ifr.ifr_flags & IFF_LOOPBACK) ? 1 : 0;
        info->is_running = (ifr.ifr_flags & IFF_RUNNING)  ? 1 : 0;
    }
    /* Interface index */
    info->index = (int)if_nametoindex(ifname);

    /* Link speed from /sys/class/net/<name>/speed */
    char path[128];
    snprintf(path, sizeof(path), "/sys/class/net/%s/speed", ifname);
    FILE *fp = fopen(path, "r");

    if (fp) 
    {
        unsigned long speed = 0;

        if (fscanf(fp, "%lu", &speed) == 1) 
        {
            info->speed_mbps = speed;
        }
        fclose(fp);
    }
    close(fd);
    return B579_OK;
}

int b579_if_list_os(b579_ifinfo_t *list, size_t max_count) 
{
    struct if_nameindex *ifs = if_nameindex();

    if (!ifs) 
    {
        b579_error_set_errno("if_nameindex");
        return B579_ERR;
    }
    int count = 0;

    for (int i = 0; ifs[i].if_index != 0 && (size_t)count < max_count; i++) 
    {
        if (b579_if_get_os(ifs[i].if_name, &list[count]) == B579_OK) 
        {
            count++;
        }
    }
    if_freenameindex(ifs);
    return count;
}

#endif /* B579_OS_LINUX */