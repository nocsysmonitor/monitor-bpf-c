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

#include "xdp_util_kern.h"
#include "xdp_cut_pkt_def.h"

// Creates maps, specify name, type, key/value size, and map size.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key,   __u32);
    __type(value, __u32);
    __uint(max_entries, MAX_NBR_SIP_TBL);
} TBL_NAME_SIP SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key,   __u32);
    __type(value, __u64);
    __uint(max_entries, 1);
} TBL_NAME_CNT SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key,   __u32);
    __type(value, __u32);
    __uint(max_entries, 1);
} TBL_NAME_EN_SIP SEC(".maps");

// Replace BCC helpers if used in inline.
static inline int is_en_sip_filter(void) {
    uint32_t *en_flag;
    int index = 0;

    en_flag = bpf_map_lookup_elem(&TBL_NAME_EN_SIP, &index);
    if (en_flag) {
        return (*en_flag != 0);
    }
    return 0;
}

static inline int parse_ipv4(void *data, uint64_t nh_off, void *data_end) {
    struct iphdr *iph = data + nh_off;

    if ((void*)&iph[1] > data_end)
        return 0;
    return iph->protocol;
}

static inline uint16_t ipv4_len(void *data, uint64_t nh_off, void *data_end) {
    struct iphdr *iph = data + nh_off;
    return iph->ihl*4;
}

static inline uint16_t ipv4_totallen(void *data, uint64_t nh_off, void *data_end) {
    struct iphdr *iph = data + nh_off;
    return iph->tot_len;
}

static inline int parse_ipv6(void *data, uint64_t nh_off, void *data_end) {
    struct ipv6hdr *ip6h = data + nh_off;

    if ((void*)&ip6h[1] > data_end)
        return 0;
    return ip6h->nexthdr;
}

static inline void update_mod_c (void) {
    uint64_t *mod_c;
    int index = 0;
    uint64_t one = 1LLU;

    mod_c = bpf_map_lookup_elem(&TBL_NAME_CNT, &index);
    if (mod_c) {
        *mod_c += 1;
    } else {
        bpf_map_update_elem(&TBL_NAME_CNT, &index, &one, BPF_NOEXIST);
    }
}

// Content of SEC() can be anything, it is userspace program decides where to hook this BPF program.
// If multiple BPF programs locate in same file, use different content to identify.
SEC("xdp")
int xdp_cut_pkt(struct xdp_md *ctx) {
    // Only need to replace BCC helpers if any.
    // Some BPF helpers might be different in various kernel version, those shall be considered, too.

    void* data_end = (void*)(long)ctx->data_end;
    void* data = (void*)(long)ctx->data;
    struct ethhdr *eth = data;
    struct iphdr *ip;

    // drop packets
    int rc = XDP_PASS; /*RETURNCODE;*/ // let pass XDP_PASS or redirect to tx via XDP_TX
    uint16_t h_proto;
    uint64_t nh_off = 0;
    uint32_t index;
    uint16_t ip_hlength, ip_totallen;
    int32_t reset_len;

    nh_off = sizeof(*eth);

    if (data + nh_off  > data_end)
        return rc;

    h_proto = eth->h_proto;

    // parse double vlans
    #pragma unroll
    for (int i=0; i<2; i++) {
        if (h_proto == htons(ETH_P_8021Q) || h_proto == htons(ETH_P_8021AD)) {
            struct vlan_hdr *vhdr;

            vhdr = data + nh_off;
            nh_off += sizeof(struct vlan_hdr);
            if (data + nh_off > data_end)
                return rc;
            h_proto = vhdr->h_vlan_encapsulated_proto;
        }
    }

    if (h_proto == htons(ETH_P_IP)) {

        if (is_en_sip_filter()) {
            ip = data + nh_off;

            if ((void*)&ip[1] > data_end)
                return rc;

            // truncate packets only if sip is configured in sip_filter
            {
                uint32_t *count;

                count = bpf_map_lookup_elem(&TBL_NAME_SIP, &ip->saddr);

                if (! count) {
                    bpf_debug("pass sip - %lx\n", ip->saddr);
                    return XDP_PASS;
                } else {
                    bpf_debug("trunc sip - %lx\n", ip->saddr);
                }
            }
        }

        index = parse_ipv4(data, nh_off, data_end);
        ip_hlength = ipv4_len(data, nh_off, data_end);
        ip_totallen = ipv4_totallen(data, nh_off, data_end);
        //reset packet
        if(index == 17) { //udp
            nh_off = nh_off + ip_hlength + sizeof(struct udphdr);
        } else if (index == 6) { //tcp
            nh_off = nh_off + ip_hlength + sizeof(struct tcphdr);
        } else {
            return XDP_PASS;
        }

        reset_len = nh_off - (data_end - data);

        bpf_xdp_adjust_tail(ctx, reset_len);

        update_mod_c();
    } else if (h_proto == htons(ETH_P_IPV6)) { /*we won't process ipv6 extesion header*/
        index = parse_ipv6(data, nh_off, data_end);
        if(index == 17) { //udp
            nh_off = nh_off + 40 /*ipv6 h len*/ + sizeof(struct udphdr);
        } else if (index == 6) { //tcp
            nh_off = nh_off + 40 /*ipv6 h len*/ + sizeof(struct tcphdr);
        } else {
            return XDP_PASS;
        }

        reset_len = nh_off - (data_end - data);

        bpf_xdp_adjust_tail(ctx, reset_len);

        update_mod_c();
    } else
        index = 0;

    return rc;
}

// License can be GPL and/or BSD.
// But only necessary when you actually use GPL helpers, verifier will tell you.
char _license[] SEC("license") = "GPL";

