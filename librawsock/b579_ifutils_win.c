#ifdef B579_OS_WINDOWS
#include <winsock2.h>
#include <iphlpapi.h>

#include "include/b579_rawsock_internal.h"


#pragma comment(lib, "iphlpapi.lib")

b579_result_t b579_if_get_os(const char *ifname, b579_ifinfo_t *info) 
{
    B579_UNUSED(ifname);
    B579_UNUSED(info);
    /* TODO: GetAdaptersInfo implementation */
    return B579_ERR_NOSYS;
}
int b579_if_list_os(b579_ifinfo_t *list, size_t max_count) 
{
    B579_UNUSED(list);
    B579_UNUSED(max_count);
    return B579_ERR_NOSYS;
}
#endif
