#if defined(B579_OS_MACOS) || defined(B579_OS_FREEBSD)

#include "include/b579_rawsock_internal.h"

b579_result_t b579_arp_cache_lookup_os(uint32_t target_ip,uint8_t target_mac[B579_MAC_LEN]) 
{
    B579_UNUSED(target_ip); B579_UNUSED(target_mac);
    /* TODO: sysctl(NET_RT_FLAGS) implementation */
    return B579_ERR_NOSYS;
}
#endif
