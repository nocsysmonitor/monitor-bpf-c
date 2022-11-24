#include <stdint.h>
#include <linux/bpf.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#include "xdp_dedup_def.h"
#include "xdp_util_kern.h"

char _license[] SEC("license") = "GPL";

MAPS(TBL_NAME_CB) = {
    .type = BPF_MAP_TYPE_PROG_ARRAY,
    .key_size = sizeof(uint32_t),
    .value_size = sizeof(uint32_t),
    .max_entries = CB_MAX,
};

MAPS(TBL_NAME_HASH) = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(uint32_t),
    .value_size = sizeof(uint32_t),
    .max_entries = HT_MAX,
};

MAPS(TBL_NAME_OPT) = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(uint32_t),
    .value_size = sizeof(uint32_t),
    .max_entries = OP_MAX,
};

MAPS(TBL_NAME_DROP) = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(uint32_t),
    .value_size = sizeof(uint64_t),
    .max_entries = 1,
};

/* max packet len = 240 * 7 + 12 (done in CB_FIN) */
const int LOOP_MAX_LEN = CB_FIN * LOOP_MAX_ONE_ROUND * 12;

struct meta_info {
    uint32_t    a;
    uint32_t    b;
    uint32_t    c;
    uint16_t    cur_ofs;
    uint8_t     cur_step;
} __attribute__((aligned(4)));

// return -1 if failed
static inline int get_opt(uint32_t op_idx)
{
    uint32_t *opt_val;

    opt_val = bpf_map_lookup_elem(&TBL_NAME_OPT, &op_idx);

    if (opt_val)
    {
        return *opt_val;
    }

    return -1;
}

// return default value if failed
static inline uint32_t get_opt_limit(void)
{
    int ret;

    ret = get_opt(OP_HLEN);

    if ((ret < 0) || (ret == 0))
        ret = DFLT_HASH_LEN;

    return ret;
}

static inline uint32_t
jhash_rot(uint32_t x, int k)
{
    return (x << k) | (x >> (32 - k));
}

static inline void
jhash_mix(uint32_t *a, uint32_t *b, uint32_t *c)
{
      *a -= *c; *a ^= jhash_rot(*c,  4); *c += *b;
      *b -= *a; *b ^= jhash_rot(*a,  6); *a += *c;
      *c -= *b; *c ^= jhash_rot(*b,  8); *b += *a;
      *a -= *c; *a ^= jhash_rot(*c, 16); *c += *b;
      *b -= *a; *b ^= jhash_rot(*a, 19); *a += *c;
      *c -= *b; *c ^= jhash_rot(*b,  4); *b += *a;
}

static inline void
jhash_final(uint32_t *a, uint32_t *b, uint32_t *c)
{
      *c ^= *b; *c -= jhash_rot(*b, 14);
      *a ^= *c; *a -= jhash_rot(*c, 11);
      *b ^= *a; *b -= jhash_rot(*a, 25);
      *c ^= *b; *c -= jhash_rot(*b, 16);
      *a ^= *c; *a -= jhash_rot(*c,  4);
      *b ^= *a; *b -= jhash_rot(*a, 14);
      *c ^= *b; *c -= jhash_rot(*b, 24);
}

/* Returns the Jenkins hash of bytes at 'p', starting from 'basis' (finish part).
 * calculate the hash for final run (< 12 bytes).
 */
PROG(CB_NAME_FIN) (struct CTXTYPE *ctx)
{
    void                *data = (void*)(long)ctx->data;
    void                *data_end = (void*)(long)ctx->data_end;
    struct meta_info    *meta;
    uint8_t             *src_p, *dst_p;
    uint32_t            tmp_3w[3] = {0};
    uint32_t            len, limit, cur_idx;

    data_end = (void*)(long)ctx->data_end;
    data = (void*)(long)ctx->data;

    len = data_end - data; // pkt = 0 ~ len -1

    /* Check data_meta have room for meta_info struct */
    meta = (void *)(unsigned long)ctx->data_meta;
    if ((void *)&meta[1] > data)
        return XDP_PASS;

    limit = get_opt_limit();

    if (len > limit)
        len = limit;

    cur_idx  = meta->cur_ofs;
    src_p = data + (meta->cur_ofs & 0xfff);
    dst_p = (uint8_t *) tmp_3w;

    #pragma unroll
    for (int j =0; j <12; j++)
    {
        if ((cur_idx + j >= len) || (src_p +1 > (uint8_t *) data_end))
            break;

        dst_p[j] = *src_p++;
    }

    meta->a += bpf_ntohl(tmp_3w[0]);
    meta->b += bpf_ntohl(tmp_3w[1]);
    meta->c += bpf_ntohl(tmp_3w[2]);

    jhash_final(&meta->a, &meta->b, &meta->c);

    if (get_opt(OP_DBG) > 0)
    {
        bpf_debug("pf ofs  - %d" DBGLR, (void *)src_p - data);
        bpf_debug("pf hash - %x" DBGLR, meta->c);
    }

    bpf_tail_call(ctx, &TBL_NAME_CB, CB_MATCH);

    return XDP_PASS;
}

/* Returns the Jenkins hash of bytes at 'p', starting from 'basis'.
 * caculate hash for part0 (<= 240 bytes)
 */
PROG(CB_NAME_P0) (struct CTXTYPE *ctx)
{
    void                *data;
    void                *data_end;
    struct meta_info    *meta;
    uint32_t            a, b, c, cur_idx =0,
                        tmp_3w[3] = {0};
    uint32_t            len, limit;
    uint8_t             *src_p, *dst_p;
    int                 ret, basis = 0;

    ret = bpf_xdp_adjust_meta(ctx, -(int)sizeof(*meta));
    if (ret < 0)
        return XDP_PASS;

    data = (void*)(long)ctx->data;
    data_end = (void*)(long)ctx->data_end;

    len = data_end - data; // pkt = 0 ~ len -1

    a = b = c = 0xdeadbeef + len + basis;

    limit = get_opt_limit();

    if (get_opt(OP_DBG) > 0)
    {
        bpf_debug("p0 lim  - %d" DBGLR, limit);
    }

    if (len > limit)
        len = limit;

    #pragma unroll
    for (int i =0; i <LOOP_MAX_ONE_ROUND; i++)
    {
        if (cur_idx + 12 > len)
            break;

        src_p = data + cur_idx;
        dst_p = (uint8_t *) tmp_3w;

        #pragma unroll
        for (int j =0; j <12; j++)
        {
            if (src_p +1 > (uint8_t *) data_end)
                break;

            dst_p[j] = *src_p;
        }

        a += bpf_ntohl(tmp_3w[0]);
        b += bpf_ntohl(tmp_3w[1]);
        c += bpf_ntohl(tmp_3w[2]);
        jhash_mix(&a, &b, &c);

        cur_idx += 12;
    }

    /* Check data_meta have room for meta_info struct */
    meta = (void *)(unsigned long)ctx->data_meta;
    if ((void *)&meta[1] > data)
        return XDP_PASS;

    meta->a = a;
    meta->b = b;
    meta->c = c;
    meta->cur_ofs  = cur_idx;
    meta->cur_step = 0;

    if (get_opt(OP_DBG) > 0)
    {
        bpf_debug("p0 len  - %d" DBGLR, len);
        bpf_debug("p0 ofs  - %d" DBGLR, cur_idx);
        bpf_debug("p0 hash - %x" DBGLR, meta->c);
    }

    if (len == cur_idx)
    {
        bpf_tail_call(ctx, &TBL_NAME_CB, CB_MATCH);
    }
    else if (len <= cur_idx + 12)
    {
        bpf_tail_call(ctx, &TBL_NAME_CB, CB_FIN);
    }
    else
    {
        bpf_tail_call(ctx, &TBL_NAME_CB, CB_P1);
    }

    return XDP_PASS;
}

/* Returns the Jenkins hash of bytes at 'p', starting from 'basis'.
 * caculate hash for part1 (240 ~ 1680 bytes).
 */
PROG(CB_NAME_P1) (struct CTXTYPE *ctx)
{
    void                *data = (void*)(long)ctx->data;
    void                *data_end = (void*)(long)ctx->data_end;
    struct meta_info    *meta;
    uint32_t            a, b, c, cur_idx,
                        tmp_3w[3] = {0};
    uint32_t            len = data_end - data;
    uint8_t             *src_p, *dst_p, cur_step;
    uint32_t            limit;

    /* Check data_meta have room for meta_info struct */
    meta = (void *)(unsigned long)ctx->data_meta;
    if ((void *)&meta[1] > data)
        return XDP_PASS;

    a = meta->a;
    b = meta->b;
    c = meta->c;
    cur_idx  = meta->cur_ofs;
    meta->cur_step += 1;
    cur_step = meta->cur_step;

    limit = get_opt_limit();

    if (len > limit)
        len = limit;

    if (get_opt(OP_DBG) > 0)
    {
        bpf_debug("p%d lim  - %d" DBGLR, cur_step, limit);
    }

    #pragma unroll
    for (int i =0; i <LOOP_MAX_ONE_ROUND; i++)
    {
        if (  (cur_idx + 12 > len)
            ||(cur_idx >= LOOP_MAX_LEN)) //make verifier happy
            break;

        data = (void*)(long)ctx->data;

        src_p = data + cur_idx;
        dst_p = (uint8_t *) tmp_3w;

        #pragma unroll
        for (int j =0; j <12; j++)
        {
            if (src_p +1 > (uint8_t *) data_end)
                break;

            dst_p[j] = *src_p;
        }

        a += bpf_ntohl(tmp_3w[0]);
        b += bpf_ntohl(tmp_3w[1]);
        c += bpf_ntohl(tmp_3w[2]);
        jhash_mix(&a, &b, &c);

        cur_idx += 12;
    }

    meta->a = a;
    meta->b = b;
    meta->c = c;
    meta->cur_ofs  = cur_idx;

    if (get_opt(OP_DBG) > 0)
    {
        bpf_debug("p%d len  - %d" DBGLR, cur_step, len);
        bpf_debug("p%d ofs  - %d" DBGLR, cur_step, cur_idx);
        bpf_debug("p%d hash - %x" DBGLR, cur_step, meta->c);
    }

    if (cur_idx == len)
    {
        bpf_tail_call(ctx, &TBL_NAME_CB, CB_MATCH);
    }
    else if (len <= cur_idx + 12)
    {
        bpf_tail_call(ctx, &TBL_NAME_CB, CB_FIN);
    }
    else
    {
        bpf_tail_call(ctx, &TBL_NAME_CB, cur_step+1);
    }

    return XDP_PASS;
}

// drop the packet if hash already exists in table
PROG(CB_NAME_MATCH) (struct CTXTYPE *ctx)
{
    void                *data = (void*)(long)ctx->data;
    struct meta_info    *meta;
    uint32_t            *count;
    uint64_t            *drop_c;
    int                 rc = XDP_PASS;

    /* Check data_meta have room for meta_info struct */
    meta = (void *)(unsigned long)ctx->data_meta;
    if ((void *)&meta[1] > data)
        return XDP_PASS;

    count = bpf_map_lookup_elem(&TBL_NAME_HASH, &meta->c);

    if (count)  // check if this hash exists
    {
        *count += 1;

        drop_c = bpf_map_lookup_elem(&TBL_NAME_DROP, (uint32_t []) {0});
        if (drop_c)
        {
            *drop_c += 1;
        }
        else
        {
            bpf_map_update_elem(&TBL_NAME_DROP, (uint32_t []) {0}, (uint64_t []) {1}, BPF_NOEXIST);
        }

        rc = XDP_DROP;

        if (get_opt(OP_DBG) > 0)
        {
            bpf_debug("drop hash - %x" DBGLR, meta->c);
        }
    }
    else        // if the hash for the key doesn't exist, create one
    {
        bpf_map_update_elem(&TBL_NAME_HASH, &meta->c, (uint32_t []) {1}, BPF_NOEXIST);
    }

    return rc;
}
