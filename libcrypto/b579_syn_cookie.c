#include "include/b579_crypto_internal.h"

/* ── Initialize with random secret ── */

b579_result_t b579_syn_cookie_init(b579_syn_cookie_ctx_t *ctx) 
{
    B579_CHECK_NULL(ctx);
    b579_result_t r = b579_entropy_siphash_key(&ctx->key);

    if (B579_IS_ERR(r))
    {
        return r;
    }
    ctx->secret = b579_entropy_u64();
    B579_DBG("SYN cookie context initialized");
    return B579_OK;
}

/* ── Initialize with explicit secret ── */

void b579_syn_cookie_init_with_secret(b579_syn_cookie_ctx_t *ctx,uint64_t secret) 
{
    if (!ctx)
    {
        return;
    }
    /* Derive SipHash key from secret using splitmix64 */
    ctx->secret = secret;
    ctx->key.k0 = splitmix64(secret);
    ctx->key.k1 = splitmix64(ctx->key.k0);
}

/* ── Generate Cookie ── */

uint32_t b579_syn_cookie_generate(const b579_syn_cookie_ctx_t *ctx,uint32_t src_ip,uint16_t src_port,uint32_t dst_ip,uint16_t dst_port) 
{
    if (!ctx)
    {
        return 0;
    }
    /*
     * Hash all 4 connection parameters + secret.
     * Order matters — same order for generate and verify.
     *
     * Pack into a compact buffer:
     *   [dst_ip:4][dst_port:2][src_ip:4][src_port:2][secret:8] = 20 bytes
     */
    uint8_t data[20];
    b579_write_u32(data + 0,  dst_ip);
    b579_write_u16(data + 4,  dst_port);
    b579_write_u32(data + 6,  src_ip);
    b579_write_u16(data + 10, src_port);
    b579_write_u64(data + 12, ctx->secret);
    uint64_t hash = b579_siphash(data, sizeof(data), &ctx->key);
    /* Truncate to 32 bits for TCP sequence number */
    return (uint32_t)(hash & 0xFFFFFFFF);
}

/* ── Verify Cookie ── */

int b579_syn_cookie_verify(const b579_syn_cookie_ctx_t *ctx,uint32_t resp_src_ip,uint16_t resp_src_port,uint32_t resp_dst_ip,uint16_t resp_dst_port,uint32_t ack_num) 
{
    if (!ctx)
    {
        return 0;
    }

    /*
     * The response swaps src/dst:
     *   Response src = our original dst (the target)
     *   Response dst = our original src (us)
     *
     * So to recompute the cookie, we pass:
     *   dst_ip   = resp_src_ip   (the target we scanned)
     *   dst_port = resp_src_port
     *   src_ip   = resp_dst_ip   (our IP)
     *   src_port = resp_dst_port
     */
    uint32_t expected = b579_syn_cookie_generate(ctx,resp_dst_ip, /* Our src_ip */ resp_dst_port, /* Our src_port */ resp_src_ip, /* Our dst_ip (target) */ resp_src_port /* Our dst_port (target) */);
    /*
     * SYN-ACK: ack = our_seq + 1
     * So: ack_num - 1 should equal our cookie
     */
    return ((ack_num - 1) == expected) ? 1 : 0;
}
