
#include "include/b579_rawsock_internal.h"

/*
 * B-579 Arwah — Adapter Statistics
 *
 * Atomic counters + rate calculation.
 * Thread-safe: TX thread and RX thread can update
 * stats simultaneously without locks.
 *
 * Principle: KISS — just atomic reads, no complex aggregation
 */

b579_rawsock_stats_t b579_rawsock_get_stats(const b579_rawsock_t *sock) 
{
    b579_rawsock_stats_t stats;
    memset(&stats, 0, sizeof(stats));

    if (!sock)
    {
        return stats;
    }
    stats.packets_sent = b579_atomic_load(&sock->stat_pkts_sent);
    stats.packets_recv = b579_atomic_load(&sock->stat_pkts_recv);
    stats.bytes_sent = b579_atomic_load(&sock->stat_bytes_sent);
    stats.bytes_recv = b579_atomic_load(&sock->stat_bytes_recv);
    stats.errors_send = b579_atomic_load(&sock->stat_errors_send);
    stats.errors_recv = b579_atomic_load(&sock->stat_errors_recv);
    stats.dropped = b579_atomic_load(&sock->stat_dropped);

    /*
     * Calculate current rate:
     * rate = (current_count - last_count) / (current_time - last_time)
     *
     * We use a const_cast here because rate calculation
     * updates cached values. This is acceptable because
     * rate fields are only read by the stats reporting thread.
     */
    uint64_t now = b579_timer_nanos();
    b579_rawsock_t *mutable_sock = (b579_rawsock_t *)sock;
    uint64_t elapsed_ns = now - mutable_sock->rate_last_time_ns;

    if (elapsed_ns > 0) 
    {
        double elapsed_sec = (double)elapsed_ns / 1000000000.0;
        uint64_t delta_sent = stats.packets_sent - mutable_sock->rate_last_pkts_sent;
        uint64_t delta_recv = stats.packets_recv - mutable_sock->rate_last_pkts_recv;
        stats.send_rate_pps = (double)delta_sent / elapsed_sec;
        stats.recv_rate_pps = (double)delta_recv / elapsed_sec;
        /* Update cached values for next call */
        mutable_sock->rate_last_time_ns = now;
        mutable_sock->rate_last_pkts_sent = stats.packets_sent;
        mutable_sock->rate_last_pkts_recv = stats.packets_recv;
    }
    return stats;
}

void b579_rawsock_reset_stats(b579_rawsock_t *sock) 
{
    if (!sock)
    {
        return;
    }
    b579_atomic_store(&sock->stat_pkts_sent, 0);
    b579_atomic_store(&sock->stat_pkts_recv, 0);
    b579_atomic_store(&sock->stat_bytes_sent, 0);
    b579_atomic_store(&sock->stat_bytes_recv, 0);
    b579_atomic_store(&sock->stat_errors_send, 0);
    b579_atomic_store(&sock->stat_errors_recv, 0);
    b579_atomic_store(&sock->stat_dropped, 0);
    sock->rate_last_time_ns = b579_timer_nanos();
    sock->rate_last_pkts_sent = 0;
    sock->rate_last_pkts_recv = 0;
}































