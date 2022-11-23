#include <getopt.h>
#include <signal.h>
#include <net/if.h>
#include <unistd.h>
#include <stdbool.h>
#include <linux/if_link.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <signal.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <argp.h>

#include "xdp_util.h"
#include "xdp_rem_tnlhdr_def.h"

/* MACRO FUNCTION DECLARATIONS
 */
#define dbglvl_help     "The verbosity of debug messages (" xstr(0) \
                          "~" xstr(3) ")."

#define inf_help        "The name of interface to use."

/* DATA TYPE DECLARATIONS
 */
typedef struct {
    int     dbg_lvl;
    int     if_idx;
} arguments_t;

typedef struct {
    char    *name_p;
    int     cb_idx;
} prog_ele_t;

/* STATIC VARIABLE DEFINITIONS
 */
static arguments_t user_arguments = {
    .dbg_lvl = 0,
};

static struct argp_option user_options[] = {
    { "dbg_lvl", 'd', "level",     0, dbglvl_help, 0 },
    { "inf",     'i', "interface", 0, inf_help,    0 },
    { 0 }                                                                                           };

#define _cb_ar_one(name) \
    { xstr(CB_NAME_##name), CB_##name }

static prog_ele_t cb_prog_ar [] = {
    _cb_ar_one(ETH),
    _cb_ar_one(VLAN),
    _cb_ar_one(IP4),
    _cb_ar_one(IP6),
    _cb_ar_one(TCP),
    _cb_ar_one(UDP),
    _cb_ar_one(GRE),
    _cb_ar_one(VXLAN),
    _cb_ar_one(GTP),
    _cb_ar_one(GENEVE),
    _cb_ar_one(CUT_1),
    _cb_ar_one(CUT_2),
};

static volatile sig_atomic_t keep_running = 1;

static void sig_handler(int _) {
    (void)_;
    keep_running = 0;
}

/* Parse a single option. */
static error_t
user_parse_opt(int key, char *arg, struct argp_state *state)
{
    /* Get the input argument from argp_parse, which we
       know is a pointer to our arguments structure. */
    arguments_t *arguments_p = state->input;

    switch (key)
    {
    case 'd':
        errno = 0;

        arguments_p->dbg_lvl = strtoul(arg, NULL, 0);
        if (errno != 0) {
            argp_error(state, "Invalid level \"%s\"", arg);
            return errno;
        }
        break;

    case 'i':
        arguments_p->if_idx = if_nametoindex(arg);
        if (errno != 0) {
            argp_error(state, "Invalid interface name \"%s\"", arg);
            return errno;
        }
        break;

    case ARGP_KEY_ARG:
        /* Too many arguments. */
        if (state->arg_num >= 2)
            argp_usage (state);

        break;

    case ARGP_KEY_END:
        if (arguments_p->if_idx == 0) {
            argp_failure(state, 1, 0, "interface is required. See --help for more information");
            exit(ARGP_ERR_UNKNOWN);
        }

    default:
        return ARGP_ERR_UNKNOWN;
    }

    return 0;
}

static void enable_opt(struct bpf_object *obj, uint32_t op_idx) {
    static char *name_ar [] = {
        [OP_DBG]    = "DBG",
        [OP_VXLAN]  = "VXLAN",
        [OP_GTP]    = "GTP",
        [OP_GRE]    = "GRE",
        [OP_GENEVE] = "GENEVE",                                                                         };
    int tbl_fd, ret;                                                                                                                                                                                        tbl_fd = bpf_object__find_map_fd_by_name(obj, xstr(TBL_NAME_OPT));
    if (tbl_fd < 0) {
        fprintf(stderr, "ERROR: finding %s in obj file failed\n", xstr(TBL_NAME_OPT));
        return;
    }

    ret = bpf_map_update_elem(tbl_fd, &op_idx, (uint32_t []) {1}, BPF_ANY);
    if (ret < 0) {
        fprintf(stderr, "ERROR: enable option (%d/%s) failed\n", op_idx, name_ar[op_idx]);
    }
}

static void dump_cnt_tbl(int map_fd, uint32_t cnt) {
    static char *name_ar [] = {
        [CNT_VXLAN]  = "VXLAN",
        [CNT_GTP]    = "GTP",
        [CNT_GRE]    = "GRE",
        [CNT_GENEVE] = "GENEVE",
    };

    uint32_t idx;
    uint32_t value;
    int err;

    if (cnt % 10 != 0)
        return;

    for (idx =0; idx < CNT_MAX; idx++) {

        err = bpf_map_lookup_elem(map_fd, &idx, &value);
        if (err) {
            fprintf(stderr, "get cnt failed (%d)...\n", idx);
            continue;
        }

        printf("idx/name/value - %04x/%6s/%08x\n", idx, name_ar[idx], value);
    }
    printf("\n");
}

int main(int argc, char **argv) {
	char filename[256];
    char filepath[256];

    int main_fd, err, fd, cb_tbl_fd, cnt_tbl_fd;
    struct bpf_program *prog;
    struct bpf_object *obj;

    /* Our argp parser. */
    static struct argp argp = { user_options, user_parse_opt, NULL, NULL };
                                                                                                        /* Parse our arguments; every option seen by `parse_opt' will be
     * reflected in arguments.
     */                                                                                                 argp_parse(&argp, argc, argv, 0, 0, &user_arguments);

	snprintf(filename, sizeof(filename), "%s_kern.o", argv[0]);
    if (NULL == get_prog_path(filepath, sizeof(filepath), filename)) {
        fprintf(stderr, "ERR: failed to get path of BPF-OBJ file(%s)\n",
            filename);
        return -1;
    }

    obj = bpf_object__open_file(filename, NULL);
    if (libbpf_get_error(obj)) {
        fprintf(stderr, "ERROR: opening BPF object file failed\n");
        return 0;
    }

    /* load BPF program */
    if (bpf_object__load(obj)) {
        fprintf(stderr, "ERROR: loading BPF object file failed\n");
        return -1;
    }

    cb_tbl_fd = bpf_object__find_map_fd_by_name(obj, xstr(TBL_NAME_CB));
    if (cb_tbl_fd < 0) {
        fprintf(stderr, "ERROR: finding %s in obj file failed\n", xstr(TBL_NAME_CB));
        return -1;
    }

    cnt_tbl_fd = bpf_object__find_map_fd_by_name(obj, xstr(TBL_NAME_CNT));
    if (cnt_tbl_fd < 0) {
        fprintf(stderr, "ERROR: finding %s in obj file failed\n", xstr(TBL_NAME_CNT));
        return -1;
    }

    if (user_arguments.dbg_lvl > 0) {
        enable_opt(obj, OP_DBG);
    }

    // defable enable VXLAN/GRE/GTP/GENEVE
    enable_opt(obj, OP_VXLAN);
    enable_opt(obj, OP_GTP);
    enable_opt(obj, OP_GRE);
    enable_opt(obj, OP_GENEVE);

    /* install program to cb_table */
    for (int idx = 0; idx < sizeof(cb_prog_ar) / sizeof(cb_prog_ar[0]); idx++) {
        prog = bpf_object__find_program_by_name(obj, cb_prog_ar[idx].name_p);
        if (!prog) {
            printf("finding a prog in obj file failed - (%s)\n", cb_prog_ar[idx].name_p);
            return -1;
        }

        fd = bpf_program__fd(prog);
        bpf_map_update_elem(cb_tbl_fd, &idx, &fd, BPF_ANY);

        if (idx == 0) {
            main_fd = fd;
        }
    }

    /* Attach BPF program to interface */
    err = bpf_set_link_xdp_fd(user_arguments.if_idx, main_fd, XDP_FLAGS_UPDATE_IF_NOEXIST);
    if (err) {
        fprintf(stderr, "ERR: ifindex(%d) link set xdp fd failed (%d): %s\n",
            user_arguments.if_idx, err, strerror(-err));
        return err;
    }
    printf("BPF attatched to interface: %d\n", user_arguments.if_idx);

    /* Keep going */
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);
    printf("Ctrl+c to exit and unload BPF\n");
    while(keep_running) {
        static uint32_t cnt = 1;

        dump_cnt_tbl(cnt_tbl_fd, cnt ++);

        usleep(1000000); // 1 sec
    }
    printf("Stopped, start to unload BPF\n");

    /* Detach XDP from interface */
    if ((err = bpf_set_link_xdp_fd(user_arguments.if_idx, -1, XDP_FLAGS_UPDATE_IF_NOEXIST)) < 0) {
        fprintf(stderr, "ERR: link set xdp unload failed (err=%d):%s\n",
            err, strerror(-err));
        return err;
    }

    printf("Done\n");
    return 0;
}
