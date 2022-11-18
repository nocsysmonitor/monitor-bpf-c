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
#include "xdp_dedup_def.h"

/* MACRO FUNCTION DECLARATIONS
 */
#define dbglvl_help     "The verbosity of debug messages (" xstr(0) \
                          "~" xstr(3) ")."

#define inf_help        "The name of interface to use."
#define sip_help        "The source ipv4 address to filter."

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

static prog_ele_t cb_prog_ar [] = {
    { xstr(CB_NAME_P0),    0 },
    { xstr(CB_NAME_P1),    1 },
    { xstr(CB_NAME_P1),    2 },
    { xstr(CB_NAME_P1),    3 },
    { xstr(CB_NAME_P1),    4 },
    { xstr(CB_NAME_P1),    5 },
    { xstr(CB_NAME_P1),    6 },
    { xstr(CB_NAME_FIN),   7 },
    { xstr(CB_NAME_MATCH), 8 },
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

static void enable_dbg_msg (struct bpf_object *obj) {
    int tbl_fd, ret;

    tbl_fd = bpf_object__find_map_fd_by_name(obj, xstr(TBL_NAME_OPT));
    if (tbl_fd < 0) {
        fprintf(stderr, "ERROR: finding %s in obj file failed\n", xstr(TBL_NAME_OPT));
        return;
    }

    ret = bpf_map_update_elem(tbl_fd, (uint32_t []) {OP_DBG}, (uint32_t []) {1}, BPF_ANY);
    if (ret < 0) {
        fprintf(stderr, "ERROR: enable dbg message failed\n");
    }
}

static void clear_hash_elements(int map_fd, uint32_t cnt) {
    uint32_t *cur_key = NULL;
    uint32_t next_key;
    uint32_t value;
    int err;

    for (;;) {
        err = bpf_map_get_next_key(map_fd, cur_key, &next_key);
        if (err) {
            if ((NULL == cur_key) && (cnt % 10 == 0))
                printf("no hash key exists...\n");
            break;
        }

        bpf_map_lookup_elem(map_fd, &next_key, &value);
        bpf_map_update_elem(map_fd, &next_key, (uint32_t []) {0}, BPF_ANY);

        if (cnt % 10 == 0)
            printf("reset key/value - %08x/%08x\n", next_key, value);

        cur_key = &next_key;
    }
}

int main(int argc, char **argv) {
	char filename[256];
    char filepath[256];

    int main_fd, err, fd, cb_tbl_fd, hash_tbl_fd;
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

    hash_tbl_fd = bpf_object__find_map_fd_by_name(obj, xstr(TBL_NAME_HASH));
    if (hash_tbl_fd < 0) {
        fprintf(stderr, "ERROR: finding %s in obj file failed\n", xstr(TBL_NAME_HASH));
        return -1;
    }


    if (user_arguments.dbg_lvl > 0) {
       enable_dbg_msg(obj);
    }

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

        cnt = (user_arguments.dbg_lvl > 0) ? cnt+1 : cnt;

        // reset hash table in 500 ms (default)
        clear_hash_elements(hash_tbl_fd, cnt);
        usleep(SLEEP_TIME_IN_US);
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
