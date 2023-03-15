#include <linux/bpf.h>
// bpf_helpers.h header file locates at /kernel-src/tools/testing/selftests
// It defines map struct and SEC(), etc.
// Or you 'll have to define those by yourself.
#include <bpf/bpf_helpers.h>

#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/if_vlan.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <stdint.h>
#include <arpa/inet.h>

#include <linux/gtp.h>
#include <linux/if_tunnel.h>

#include <net/gre.h>
#include <net/geneve.h>
#include <net/vxlan.h>
#include <net/gtp.h>

#include "xdp_rem_tnlhdr_def.h"
#include "xdp_util_kern.h"

char _license[] SEC("license") = "GPL";

struct meta_info {
    uint8_t hdr_len[CB_MAX];
    uint8_t cur_ofs;
} __attribute__((aligned(4)));

struct meta_info_cut {
    uint16_t    hdr_len[2];     // 0 - l2 hdr len (including ether type), 1 - cut len
    uint8_t     is_inner_ip4;   // to modify ethertype
    uint8_t     is_outer_ip4;
    uint8_t     cn_id;          // refer to cn_idx
} __attribute__((aligned(4)));

static int cb_vlan(struct CTXTYPE *ctx);
static int cb_ip4(struct CTXTYPE *ctx);
static int cb_ip6(struct CTXTYPE *ctx);
static int cb_gre(struct CTXTYPE *ctx);
static int cb_udp(struct CTXTYPE *ctx);
static int cb_tcp(struct CTXTYPE *ctx);
static int cb_vxlan(struct CTXTYPE *ctx);
static int cb_gtp(struct CTXTYPE *ctx);
static int cb_geneve(struct CTXTYPE *ctx);
static int cb_cut_1(struct CTXTYPE *ctx);
static int cb_cut_2(struct CTXTYPE *ctx);

struct {                // 0: off, 1: on
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key,   __u32);
    __type(value, __u32);
    __uint(max_entries, OP_MAX);
} TBL_NAME_OPT SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key,   __u32);
    __type(value, __u64);
    __uint(max_entries, CNT_MAX);
} TBL_NAME_CNT SEC(".maps");

static inline int is_opt_on(uint32_t opt_idx)
{
    uint32_t *opt_flag;

    opt_flag = bpf_map_lookup_elem(&TBL_NAME_OPT, &opt_idx);

    if (opt_flag)
    {
        return (*opt_flag != 0);
    }

    return 0;
}

static inline void update_rem_total(uint32_t idx)
{
    uint64_t *rem_c;

    rem_c = bpf_map_lookup_elem(&TBL_NAME_CNT, &idx);

    if (rem_c)
    {
        *rem_c += 1;
    }
    else
    {
        bpf_map_update_elem(&TBL_NAME_CNT, &idx, (uint64_t []) {1}, BPF_NOEXIST);
    }
}

// ethtype (in network order)
// jump to next program or return -1
static inline int dispatch_ethtype(struct CTXTYPE *ctx, uint16_t ethtype)
{
    switch (ntohs(ethtype))
    {
    case ETH_P_8021Q:
    case ETH_P_8021AD:
        return cb_vlan(ctx);
    case ETH_P_IP:
        return cb_ip4(ctx);
    case ETH_P_IPV6:
        return cb_ip6(ctx);
    default:
        return XDP_PASS;
    }
}

// ethtype (in network order)
// jump to next program or return -1
static inline int dispatch_ethtype_vlan(struct CTXTYPE *ctx, uint16_t ethtype)
{
    switch (ntohs(ethtype))
    {
    case ETH_P_IP:
        return cb_ip4(ctx);
    case ETH_P_IPV6:
        return cb_ip6(ctx);
    default:
        return XDP_PASS;
    }
}

// proto (in network order)
// jump to next program or return -1
static inline int dispatch_ippro(struct CTXTYPE *ctx, uint16_t proto)
{
    switch (proto)
    {
    case IPPROTO_UDP:
        return cb_udp(ctx);
    case IPPROTO_TCP:
        return cb_tcp(ctx);
    case IPPROTO_GRE:
        if (is_opt_on(OP_GRE))
            return cb_gre(ctx);
        return XDP_PASS;
    default:
        return XDP_PASS;
    }
}

// port (in network order)
// jump to next program or return -1
static inline int dispatch_port(struct CTXTYPE *ctx, uint16_t port)
{
    switch (ntohs(port))
    {
    case 4789:
        if (is_opt_on(OP_VXLAN))
            return cb_vxlan(ctx);
        break;
    case GTP1U_PORT:
        if (is_opt_on(OP_GTP))
            return cb_gtp(ctx);
        break;
    case GENEVE_UDP_PORT:
        if (is_opt_on(OP_GENEVE))
            return cb_geneve(ctx);
        break;
    default:
        break;
    }

    return XDP_PASS;
}

SEC("xdp")
int xdp_rem_tnlhdr(struct CTXTYPE *ctx)
{
    // It seems 'Tail Call' is not supported in  LIBXDP,
    // so make every 'tail call' to 'BPF to BPF' function call.
    // Also change the function name from 'cb_eth' to 'xdp_rem_tnlhdr',
    // which can be showed by tool 'xdp-loader'.
    void            *data_end;
    void            *data;
    struct          meta_info *meta;
    struct ethhdr   *eth;
    int             ret;

//    if (! (is_opt_on(OP_VXLAN) || (is_opt_on(OP_GTP))))
//        return XDP_PASS;

    ret = bpf_xdp_adjust_meta(ctx, -(int)sizeof(*meta));
    if (ret < 0)
        return XDP_PASS;

    data_end = (void*)(long)ctx->data_end;
    data = (void*)(long)ctx->data;

    /* Check data_meta have room for meta_info struct */
    meta = (void *)(unsigned long)ctx->data_meta;
    if ((void *)&meta[1] > data)
        return XDP_PASS;

    #pragma unroll
    for (int i=0; i <sizeof(meta->hdr_len); i++)
    {
        meta->hdr_len[i] = 0;
    }

    eth = data;
    if ((void *)&eth[1] > data_end)
        return XDP_PASS;

    meta->hdr_len[CB_ETH] = sizeof(*eth);
    meta->cur_ofs = sizeof(*eth);

    if (is_opt_on(OP_DBG))
    {
        bpf_debug("eth ofs - %d" DBGLR, meta->cur_ofs);
    }

    return dispatch_ethtype(ctx, eth->h_proto);
}

static int cb_vlan(struct CTXTYPE *ctx)
{
    void            *data_end;
    void            *data;
    struct          meta_info *meta;
    struct vlan_hdr *vhdr;
    int             len = 0, cur_ofs;
    uint16_t        next_proto;

    data_end = (void*)(long)ctx->data_end;
    data = (void*)(long)ctx->data;

    /* Check data_meta have room for meta_info struct */
    meta = (void *)(unsigned long)ctx->data_meta;
    if ((void *)&meta[1] > data)
        return XDP_PASS;

    cur_ofs = meta->cur_ofs;

    #pragma unroll
    for (int i=0; i<2; i++)
    {
        vhdr = data + cur_ofs + len;

        if ((void *)&vhdr[1] > data_end)
        {
            return XDP_PASS;
        }

        next_proto = vhdr->h_vlan_encapsulated_proto;
        len += sizeof(*vhdr);

        if (!(next_proto == htons(ETH_P_8021Q) || next_proto == htons(ETH_P_8021AD)))
        {
            break;
        }
    }

    meta->hdr_len[CB_VLAN] = len;
    meta->cur_ofs = cur_ofs + len;

    if (is_opt_on(OP_DBG))
    {
        bpf_debug("vlan ofs - %d" DBGLR, meta->cur_ofs);
    }

    return dispatch_ethtype_vlan(ctx, next_proto);
}

static int cb_ip4(struct CTXTYPE *ctx)
{
    void                *data_end;
    void                *data;
    struct meta_info    *meta;
    struct iphdr        *iph;

    data_end = (void*)(long)ctx->data_end;
    data = (void*)(long)ctx->data;

    /* Check data_meta have room for meta_info struct */
    meta = (void *)(unsigned long)ctx->data_meta;
    if ((void *)&meta[1] > data)
        return XDP_PASS;

    iph = data + meta->cur_ofs;
    if ((void *)&iph[1] > data_end)
        return XDP_PASS;

    meta->hdr_len[CB_IP4] = iph->ihl << 2;
    meta->cur_ofs += iph->ihl << 2;

    if (is_opt_on(OP_DBG))
    {
        bpf_debug("ip4 ofs - %d" DBGLR, meta->cur_ofs);
    }

    return dispatch_ippro(ctx, iph->protocol);
}

static int cb_ip6(struct CTXTYPE *ctx)
{
    void                *data_end;
    void                *data;
    struct meta_info    *meta;
    struct ipv6hdr      *ip6h;

    data_end = (void*)(long)ctx->data_end;
    data = (void*)(long)ctx->data;

    /* Check data_meta have room for meta_info struct */
    meta = (void *)(unsigned long)ctx->data_meta;
    if ((void *)&meta[1] > data)
        return XDP_PASS;

    ip6h = data + meta->cur_ofs;
    if ((void *)&ip6h[1] > data_end)
        return XDP_PASS;

    meta->hdr_len[CB_IP6] = sizeof(*ip6h);
    meta->cur_ofs += sizeof(*ip6h);

    if (is_opt_on(OP_DBG))
    {
        bpf_debug("ip6 ofs - %d" DBGLR, meta->cur_ofs);
    }

    return dispatch_ippro(ctx, ip6h->nexthdr);
}

//refer to gre_parse_header in linux kernel
static int cb_gre(struct CTXTYPE *ctx)
{
    void                *data_end;
    void                *data;
    struct meta_info    *meta;
    struct gre_base_hdr *greh;
    int                 hdr_len;

    data_end = (void*)(long)ctx->data_end;
    data = (void*)(long)ctx->data;

    /* Check data_meta have room for meta_info struct */
    meta = (void *)(unsigned long)ctx->data_meta;
    if ((void *)&meta[1] > data)
        return XDP_PASS;

    greh = data + meta->cur_ofs;

    if ((void *)&greh[1] > data_end)
        return XDP_PASS;

    hdr_len = gre_calc_hlen(greh->flags);

    meta->hdr_len[CB_GRE] = hdr_len;

    meta->cur_ofs += hdr_len;

    if (is_opt_on(OP_DBG))
    {
        bpf_debug("gre ofs - %d" DBGLR, meta->cur_ofs);
    }

    {
        int                     cut_len, l2_hdr_len;
        uint8_t                 is_outer_ip4 = 0;
        uint8_t                 is_inner_ip4 = 0;
        struct meta_info_cut    *meta_cut;

        // need to cut inserted (ip/gre) part
        //    cut_len max: 60 + 16
        // l2_hdr_len max: 14 + 8
        cut_len    = meta->hdr_len[CB_IP4] + meta->hdr_len[CB_IP6] +
                     meta->hdr_len[CB_GRE];
        l2_hdr_len = meta->hdr_len[CB_ETH] + meta->hdr_len[CB_VLAN];

        is_outer_ip4 = (meta->hdr_len[CB_IP4] > 0);
        is_inner_ip4 = (greh->protocol == htons(ETH_P_IP));

        meta_cut = (void *)(unsigned long)ctx->data_meta;
        if ((void *)&meta_cut[1] > data)
            return XDP_PASS;

        meta_cut->hdr_len[0] = l2_hdr_len;
        meta_cut->hdr_len[1] = cut_len;
        meta_cut->is_outer_ip4 = is_outer_ip4;
        meta_cut->is_inner_ip4 = is_inner_ip4;
        meta_cut->cn_id = CNT_GRE;

        return cb_cut_1(ctx);
    }
}

static int cb_udp(struct CTXTYPE *ctx)
{
    void                *data_end;
    void                *data;
    struct meta_info    *meta;
    struct udphdr       *udph;

    data_end = (void*)(long)ctx->data_end;
    data = (void*)(long)ctx->data;

    /* Check data_meta have room for meta_info struct */
    meta = (void *)(unsigned long)ctx->data_meta;
    if ((void *)&meta[1] > data)
        return XDP_PASS;

    udph = data + meta->cur_ofs;

    if ((void *)&udph[1] > data_end)
        return XDP_PASS;

    meta->hdr_len[CB_UDP] = sizeof(*udph);
    meta->cur_ofs += sizeof(*udph);

    if (is_opt_on(OP_DBG))
    {
        bpf_debug("udp ofs - %d" DBGLR, meta->cur_ofs);
    }

    return dispatch_port(ctx, udph->dest);
}

static int cb_tcp(struct CTXTYPE *ctx)
{
    void                *data_end;
    void                *data;
    struct meta_info    *meta;
    struct tcphdr       *tcph;

    data_end = (void*)(long)ctx->data_end;
    data = (void*)(long)ctx->data;

    /* Check data_meta have room for meta_info struct */
    meta = (void *)(unsigned long)ctx->data_meta;
    if ((void *)&meta[1] > data)
        return XDP_PASS;

    tcph = data + meta->cur_ofs;

    if ((void *)&tcph[1] > data_end)
        return -1;

    meta->hdr_len[CB_TCP] = tcph->doff << 2;
    meta->cur_ofs += tcph->doff << 2;

    if (is_opt_on(OP_DBG))
    {
        bpf_debug("tcp ofs - %d" DBGLR,meta->cur_ofs);
    }

    return dispatch_port(ctx, tcph->dest);
}

static int cb_vxlan(struct CTXTYPE *ctx)
{
    void                *data_end;
    void                *data;
    struct meta_info    *meta;
    struct vxlanhdr     *vxlanh;
    uint8_t             cut_len;

    data_end = (void*)(long)ctx->data_end;
    data = (void*)(long)ctx->data;

    /* Check data_meta have room for meta_info struct */
    meta = (void *)(unsigned long)ctx->data_meta;
    if ((void *)&meta[1] > data)
        return XDP_PASS;

    vxlanh = data + meta->cur_ofs;

    if ((void *)&vxlanh[1] > data_end)
        return XDP_PASS;

    cut_len = meta->cur_ofs + sizeof(*vxlanh);

    if (is_opt_on(OP_DBG))
    {
        bpf_debug("vxlan ofs - %d" DBGLR, cut_len);
    }

    {
        struct meta_info_cut    *meta_cut;

        meta_cut = (void *)(unsigned long)ctx->data_meta;
        if ((void *)&meta_cut[1] > data)
            return XDP_PASS;

        meta_cut->hdr_len[1] = cut_len;
        meta_cut->cn_id = CNT_VXLAN;

        return cb_cut_2(ctx);
    }
}

static int cb_gtp(struct CTXTYPE *ctx)
{
    void                *data_end;
    void                *data;
    struct meta_info    *meta;
    //refer to gtp1u_udp_encap_recv in linux kernel
    struct gtp1_header  *gtp1h;
    int                 hdr_len = sizeof(*gtp1h);

    data_end = (void*)(long)ctx->data_end;
    data = (void*)(long)ctx->data;

    /* Check data_meta have room for meta_info struct */
    meta = (void *)(unsigned long)ctx->data_meta;
    if ((void *)&meta[1] > data)
        return XDP_PASS;

    gtp1h = data + meta->cur_ofs;

    if ((void *)&gtp1h[1] > data_end)
        return XDP_PASS;

    if ((gtp1h->flags >> 5) != GTP_V1)
        return XDP_PASS;

    if (gtp1h->type != GTP_TPDU)
        return XDP_PASS;

    if (gtp1h->flags & GTP1_F_MASK)
        hdr_len += 4;

    meta->cur_ofs += hdr_len;
    meta->hdr_len[CB_GTP] = hdr_len;

    if (is_opt_on(OP_DBG))
    {
        bpf_debug("gtp1u ofs - %d" DBGLR, meta->cur_ofs);
    }

    {
        int                     cut_len, l2_hdr_len;
        uint8_t                 is_outer_ip4 = 0;
        uint8_t                 is_inner_ip4 = 0;
        struct meta_info_cut    *meta_cut;

        // need to cut inserted (ip/udp or tcp /gprs) part
        //    cut_len max: 60 + 60 + 12
        // l2_hdr_len max: 14 + 8
        cut_len    = meta->hdr_len[CB_IP4] + meta->hdr_len[CB_IP6] +
                     meta->hdr_len[CB_TCP] + meta->hdr_len[CB_UDP] +
                     meta->hdr_len[CB_GTP];
        l2_hdr_len = meta->hdr_len[CB_ETH] + meta->hdr_len[CB_VLAN];

        meta_cut = (void *)(unsigned long)ctx->data_meta;
        if ((void *)&meta_cut[1] > data)
            return XDP_PASS;

        meta_cut->hdr_len[0] = l2_hdr_len;
        meta_cut->hdr_len[1] = cut_len;
        meta_cut->is_outer_ip4 = is_outer_ip4;
        meta_cut->is_inner_ip4 = is_inner_ip4;
        meta_cut->cn_id = CNT_GTP;

        return cb_cut_1(ctx);
    }
}

static int cb_geneve(struct CTXTYPE *ctx)
{
    void                *data_end;
    void                *data;
    struct meta_info    *meta;
    //refer to geneve_udp_encap_recv in linux kernel
    struct genevehdr    *geneveh;
    uint8_t             cut_len;

    data_end = (void*)(long)ctx->data_end;
    data = (void*)(long)ctx->data;

    /* Check data_meta have room for meta_info struct */
    meta = (void *)(unsigned long)ctx->data_meta;
    if ((void *)&meta[1] > data)
        return XDP_PASS;

    geneveh = data + meta->cur_ofs;

    if ((void *)&geneveh[1] > data_end)
        return XDP_PASS;

    if (geneveh->proto_type != htons(ETH_P_TEB))
        return XDP_PASS;

    // maximum geneve header size : 260
    cut_len = meta->cur_ofs + sizeof(*geneveh) + geneveh->opt_len * 4;

    if (is_opt_on(OP_DBG))
    {
        bpf_debug("geneve ofs - %d" DBGLR, cut_len);
    }

    {
        struct meta_info_cut    *meta_cut;

        meta_cut = (void *)(unsigned long)ctx->data_meta;
        if ((void *)&meta_cut[1] > data)
            return XDP_PASS;

        meta_cut->hdr_len[1] = cut_len;
        meta_cut->cn_id = CNT_GENEVE;

        return cb_cut_2(ctx);
    }
}

// remove inserted header in the middle
static int cb_cut_1(struct CTXTYPE *ctx)
{
    void                    *data_end;
    void                    *data;
    struct meta_info_cut    *meta;

    data_end = (void*)(long)ctx->data_end;
    data = (void*)(long)ctx->data;

    /* Check data_meta have room for meta_info struct */
    meta = (void *)(unsigned long)ctx->data_meta;
    if ((void *)&meta[1] > data)
        return XDP_PASS;

    if (is_opt_on(OP_DBG))
    {
        bpf_debug("cut1 hdr_len[0] - %d" DBGLR, meta->hdr_len[0]);
        bpf_debug("cut1 hdr_len[1] - %d" DBGLR, meta->hdr_len[1]);
        bpf_debug("cut1 is_inner_ip4 - %d" DBGLR, meta->is_inner_ip4);
        bpf_debug("cut1 is_outer_ip4 - %d" DBGLR, meta->is_outer_ip4);
    }

    {
        int         cut_len, l2_hdr_len, cn_id;

        // need to cut inserted part
        // l2_hdr_len max: 14 + 8
        cut_len    = meta->hdr_len[1];
        l2_hdr_len = meta->hdr_len[0];
        cn_id      = meta->cn_id;

        if (meta->is_inner_ip4 != meta->is_outer_ip4)
        {
            // need to modify the ethertype
            l2_hdr_len -= 2;
        }

        // move eth + vlan headear forward to strip the gtp tunnel header
        // Not sure what below codes do, but compiled BPF fails to load with them.
	/*for (int i=0; i <22; i++)
        {
            char *src, *dst;

            if (i > l2_hdr_len)
                break;

            src = data + i;
            if (&src[1] > (char *)data_end)
                return XDP_PASS;

            dst = data + i + (cut_len & 0xff); // make verifier happy
            if (&dst[1] > (char *)data_end)
                return XDP_PASS;

            *dst = *src;
        }*/

        if (meta->is_inner_ip4 != meta->is_outer_ip4)
        {
            char *dst;

            // need to modify the ethertype
            dst = data + (l2_hdr_len & 0xff) + (cut_len & 0xff); // make verifier happy
            if (&dst[2] > (char *)data_end)
                return XDP_PASS;

            if (!meta->is_inner_ip4)
            {
                dst[0] = 0x86;
                dst[1] = 0xdd;
            }
            else
            {
                dst[0] = 0x08;
                dst[1] = 0x00;
            }
        }

        bpf_xdp_adjust_head(ctx, cut_len);

        update_rem_total(cn_id);
    }

    return XDP_PASS;
}

//remove inserted header from head
static int cb_cut_2(struct CTXTYPE *ctx)
{
    void                    *data_end;
    void                    *data;
    struct meta_info_cut    *meta;
    int                     cn_id;

    data_end = (void*)(long)ctx->data_end;
    data = (void*)(long)ctx->data;

    /* Check data_meta have room for meta_info struct */
    meta = (void *)(unsigned long)ctx->data_meta;
    if ((void *)&meta[1] > data)
        return XDP_PASS;

    cn_id = meta->cn_id;

    if (is_opt_on(OP_DBG))
    {
        bpf_debug("cut2 ofs - %d" DBGLR, meta->hdr_len[1]);
    }

    bpf_xdp_adjust_head(ctx, meta->hdr_len[1]);

    update_rem_total(cn_id);

    return XDP_PASS;
}
