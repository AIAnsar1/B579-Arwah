#ifdef B579_OS_WINDOWS

#include "include/b579_rawsock_internal.h"

b579_result_t b579_route_get_os(uint32_t dst_ip, b579_route_t *route) 
{
    B579_UNUSED(dst_ip); B579_UNUSED(route);
    /* TODO: GetBestRoute implementation */
    return B579_ERR_NOSYS;
}

int b579_route_list_os(b579_route_t *list, size_t max_count) 
{
    B579_UNUSED(list); B579_UNUSED(max_count);
    return B579_ERR_NOSYS;
}
#endif
