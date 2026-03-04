#ifdef B579_OS_WINDOWS

#include <winsock2.h>
#include <iphlpapi.h>

#include "include/b579_rawsock_internal.h"


b579_result_t b579_arp_cache_lookup_os(uint32_t target_ip,uint8_t target_mac[B579_MAC_LEN]) 
{
    ULONG mac[2];
    ULONG mac_len = 6;
    DWORD ret = SendARP(htonl(target_ip), 0, mac, &mac_len);
    
    if (ret == NO_ERROR && mac_len == 6) 
    {
        memcpy(target_mac, mac, B579_MAC_LEN);
        return B579_OK;
    }
    return B579_ERR;
}
#endif