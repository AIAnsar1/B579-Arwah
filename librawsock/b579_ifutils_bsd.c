#if defined(B579_OS_MACOS) || defined(B579_OS_FREEBSD)
#include <ifaddrs.h>
#include <net/if.h>
#include <net/if_dl.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include "include/b579_rawsock_internal.h"


b579_result_t b579_if_get_os(const char *ifname, b579_ifinfo_t *info) 
{
    struct ifaddrs *ifap, *ifa;

    if (getifaddrs(&ifap) < 0) 
    {
        b579_error_set_errno("getifaddrs");
        return B579_ERR;
    }
    strncpy(info->name, ifname, B579_IFNAME_MAX - 1);

    for (ifa = ifap; ifa; ifa = ifa->ifa_next) 
    {
        if (strcmp(ifa->ifa_name, ifname) != 0)
        {
            continue;
        }
        info->is_up = (ifa->ifa_flags & IFF_UP)       ? 1 : 0;
        info->is_loopback = (ifa->ifa_flags & IFF_LOOPBACK) ? 1 : 0;
        info->is_running = (ifa->ifa_flags & IFF_RUNNING)  ? 1 : 0;

        if (ifa->ifa_addr && ifa->ifa_addr->sa_family == AF_INET) 
        {
            struct sockaddr_in *sin = (struct sockaddr_in *)ifa->ifa_addr;
            info->ipv4 = ntohl(sin->sin_addr.s_addr);
        }

        if (ifa->ifa_addr && ifa->ifa_addr->sa_family == AF_LINK) 
        {
            struct sockaddr_dl *sdl = (struct sockaddr_dl *)ifa->ifa_addr;

            if (sdl->sdl_alen == B579_MAC_LEN) 
            {
                memcpy(info->mac, LLADDR(sdl), B579_MAC_LEN);
            }
        }
    }
    info->index = (int)if_nametoindex(ifname);
    freeifaddrs(ifap);
    return B579_OK;
}

int b579_if_list_os(b579_ifinfo_t *list, size_t max_count) 
{
    struct if_nameindex *ifs = if_nameindex();

    if (!ifs)
    {
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
#endif
