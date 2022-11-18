#ifndef _XDP_DEDUP_DEF_H_
#define _XDP_DEDUP_DEF_H_

#define SLEEP_TIME_IN_MS    500
#define SLEEP_TIME_IN_US    (SLEEP_TIME_IN_MS * 1000)

#define CB_NAME_P0      cb_hash_p0
#define CB_NAME_P1      cb_hash_p1
#define CB_NAME_FIN     cb_hash_fin
#define CB_NAME_MATCH   cb_hash_match

#define TBL_NAME_OPT    opt_tbl
#define TBL_NAME_CB     cb_tbl
#define TBL_NAME_HASH   packet_hash
#define TBL_NAME_DROP   drop_total 

enum op_idx {
    OP_DBG,
    OP_HLEN,
    OP_MAX,
};

#endif

