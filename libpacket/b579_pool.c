#include <stdlib.h>

#include "include/b579_packet_internal.h"

/* ── Internal: free list node ── */
typedef struct pool_node {
    struct pool_node *next;
    b579_pkt_buf_t    buf;
} pool_node_t;

/* ── Pool structure ── */
struct b579_pkt_pool {
    pool_node_t *nodes;           /* Array of all nodes */
    uint8_t *memory;          /* Contiguous buffer memory */
    size_t num_buffers;     /* Total buffer count */
    size_t buffer_size;     /* Size of each buffer */
    /* Lock-free free list (atomic LIFO stack) */
    /* Using simple pointer for now — upgrade to CAS if needed */
    pool_node_t * volatile free_head;
    /* Stats */
    b579_atomic_u64 stat_gets;
    b579_atomic_u64 stat_puts;
    b579_atomic_u64 stat_empty;      /* Times pool was empty */
};

/* ── Create ── */

b579_pkt_pool_t *b579_pool_create(size_t num_buffers, size_t buffer_size) 
{
    if (num_buffers == 0 || buffer_size == 0)
    {
        return NULL;
    }

    b579_pkt_pool_t *pool = (b579_pkt_pool_t *)b579_malloc(sizeof(*pool));

    if (!pool)
    {
        return NULL;
    }
    pool->num_buffers = num_buffers;
    pool->buffer_size = buffer_size;
    /* Allocate node array */
    pool->nodes = (pool_node_t *)b579_calloc(num_buffers, sizeof(pool_node_t));

    if (!pool->nodes) 
    {
        b579_free(pool, sizeof(*pool));
        return NULL;
    }
    /* Allocate contiguous buffer memory */
    pool->memory = (uint8_t *)b579_malloc(num_buffers * buffer_size);

    if (!pool->memory) 
    {
        b579_free(pool->nodes, num_buffers * sizeof(pool_node_t));
        b579_free(pool, sizeof(*pool));
        return NULL;
    }
    /* Initialize all nodes and build free list */
    pool->free_head = NULL;

    for (size_t i = 0; i < num_buffers; i++) 
    {
        pool->nodes[i].buf.data = pool->memory + (i * buffer_size);
        pool->nodes[i].buf.capacity = buffer_size;
        pool->nodes[i].buf.length = 0;
        /* Push to free list (LIFO) */
        pool->nodes[i].next = pool->free_head;
        pool->free_head = &pool->nodes[i];
    }

    b579_atomic_init(&pool->stat_gets,  0);
    b579_atomic_init(&pool->stat_puts,  0);
    b579_atomic_init(&pool->stat_empty, 0);
    B579_DBG("packet pool created: %zu buffers × %zu bytes = %zu KB",num_buffers, buffer_size,(num_buffers * buffer_size) / 1024);
    return pool;
}

/* ── Destroy ── */

void b579_pool_destroy(b579_pkt_pool_t *pool) 
{
    if (!pool)
    {
        return;
    }
    B579_DBG("pool stats: gets=%llu puts=%llu empty=%llu",(unsigned long long)b579_atomic_load(&pool->stat_gets),(unsigned long long)b579_atomic_load(&pool->stat_puts),(unsigned long long)b579_atomic_load(&pool->stat_empty));
    b579_free(pool->memory, pool->num_buffers * pool->buffer_size);
    b579_free(pool->nodes,  pool->num_buffers * sizeof(pool_node_t));
    b579_free(pool, sizeof(*pool));
}

/* ── Get buffer (pop from free list) ── */

b579_pkt_buf_t *b579_pool_get(b579_pkt_pool_t *pool) 
{
    if (!pool)
    {
        return NULL;
    }
    pool_node_t *node = pool->free_head;

    if (B579_UNLIKELY(!node)) 
    {
        b579_atomic_inc(&pool->stat_empty);
        return NULL; /* Pool exhausted */
    }
    pool->free_head = node->next;
    node->next = NULL;
    node->buf.length = 0;
    b579_atomic_inc(&pool->stat_gets);
    return &node->buf;
}

/* ── Return buffer (push to free list) ── */

void b579_pool_put(b579_pkt_pool_t *pool, b579_pkt_buf_t *buf) 
{
    if (!pool || !buf)
    {
        return;
    }
    /*
     * Recover node pointer from buf pointer.
     * buf is embedded in pool_node_t, so we can get the node
     * by offsetting backward.
     */
    pool_node_t *node = (pool_node_t *)((uint8_t *)buf - offsetof(pool_node_t, buf));
    /* Clear buffer data (prevent info leaks between uses) */
    node->buf.length = 0;
    /* Push to free list */
    node->next = pool->free_head;
    pool->free_head = node;
    b579_atomic_inc(&pool->stat_puts);
}

/* ── Available count ── */

size_t b579_pool_available(const b579_pkt_pool_t *pool) 
{
    if (!pool)
    {
        return 0;
    }
    size_t count = 0;
    pool_node_t *node = pool->free_head;

    while (node) 
    {
        count++;
        node = node->next;
    }
    return count;
}


