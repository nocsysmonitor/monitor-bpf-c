#ifndef _XDP_REM_TNLHDR_DEF_H_

#define CB_NAME_ETH     cb_eth
#define CB_NAME_VLAN    cb_vlan
#define CB_NAME_IP4     cb_ip4
#define CB_NAME_IP6     cb_ip6
#define CB_NAME_TCP     cb_tcp
#define CB_NAME_UDP     cb_udp
#define CB_NAME_GRE     cb_gre
#define CB_NAME_VXLAN   cb_vxlan
#define CB_NAME_GTP     cb_gtp
#define CB_NAME_GENEVE  cb_geneve
#define CB_NAME_CUT_1   cb_cut_1
#define CB_NAME_CUT_2   cb_cut_2

#define TBL_NAME_OPT    opt_tbl
#define TBL_NAME_CB     cb_tbl
#define TBL_NAME_CNT    cnt_tbl

enum cnt_idx {
    CNT_VXLAN,
    CNT_GTP,
    CNT_GRE,
    CNT_GENEVE,
    CNT_MAX
};

enum cb_idx {
    CB_ETH,
    CB_VLAN,
    CB_IP4,
    CB_IP6,
    CB_TCP,
    CB_UDP,
    CB_GRE,
    CB_VXLAN,
    CB_GTP,
    CB_GENEVE,
    CB_CUT_1,
    CB_CUT_2,
    CB_MAX,
};

enum op_idx {
    OP_DBG,
    OP_VXLAN,
    OP_GTP,
    OP_GRE,
    OP_GENEVE,
    OP_MAX,
};

#define CTXTYPE     xdp_md
#define DBGLR       "\n"

#endif

