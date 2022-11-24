#include <getopt.h>
#include <signal.h>
#include <unistd.h>
#include <stdbool.h>
#include <libgen.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <argp.h>

#include <net/if.h>
#include <linux/if_link.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "xdp_util.h"
#include "xdp_rem_tnlhdr_def.h"

/* MACRO FUNCTION DECLARATIONS
 */
#define dbglvl_help     "The verbosity of debug messages (" xstr(0) \
                          "~" xstr(3) ")."

#define inf_help        "The name of interface to use."
#define en_help         "The idx of option to enable. (" xstr(0) "~" \
                          xstr(5) ")."
#define dis_help        "The idx of option to disable. (" xstr(0) "~" \
                          xstr(5) ")."


/* DATA TYPE DECLARATIONS
 */
typedef struct {
    char    *en_opt_p[OP_MAX];
    char    *dis_opt_p[OP_MAX];

    int     dbg_lvl;
    int     if_idx;
    int     en_num;
    int     dis_num;
} arguments_t;

typedef struct {
    char    *name_p;
    int     cb_idx;
} prog_ele_t;

/* STATIC VARIABLE DEFINITIONS
 */
static arguments_t user_arguments = {
    .dbg_lvl = 0,
    .en_num  = 0,
    .dis_num = 0,
};

static struct argp_option user_options[] = {
    { 0,0,0,0, "Optional:", 7 },
    { "dbg_lvl", 'd', "level",     0, dbglvl_help, 0 },
    { "en",      'e', "idx",       0, en_help,     0 },
    { "dis",     'u', "idx",       0, dis_help,    0 },
    { 0,0,0,0, "Required for loading xdp kernel program:", 5 },
    { "inf",     'i', "interface", 0, inf_help,    0 },
    {0}
};

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

    case 'e':
        arguments_p->en_opt_p[arguments_p->en_num++] = arg;
        break;

    case 'u':
        arguments_p->dis_opt_p[arguments_p->dis_num++] = arg;
        break;

    case ARGP_KEY_ARG:
        /* Too many arguments. */
        // for arguments, not for options above.
        // we do not accept any arguments
        if (state->arg_num > 0)
            argp_usage (state);

        break;

    case ARGP_KEY_END:
        if (arguments_p->if_idx == 0) {
            if (arguments_p->en_num == 0 && arguments_p->dis_num == 0) {
                argp_failure(state, 1, 0, "interface is required. See --help for more information");
                exit(ARGP_ERR_UNKNOWN);
            }
        }

    default:
        return ARGP_ERR_UNKNOWN;
    }

    return 0;
}

//static void enable_opt(struct bpf_object *obj, uint32_t op_idx, int is_en) {
static void enable_opt(int map_fd, uint32_t op_idx, int is_en) {
    static char *name_ar [] = {
        [OP_DBG]    = "DBG",
        [OP_VXLAN]  = "VXLAN",
        [OP_GTP]    = "GTP",
        [OP_GRE]    = "GRE",
        [OP_GENEVE] ="GENEVE",
    };
    int ret;

    if (is_en) {
        ret = bpf_map_update_elem(map_fd, &op_idx, (uint32_t []) {1}, BPF_ANY);
        if (ret < 0) {
            fprintf(stderr, "ERR: enable option (%d/%s) failed\n", op_idx, name_ar[op_idx]);
        } else {
            printf(" - Enable option (%s)\n", name_ar[op_idx]);
        }

    } else {
        ret = bpf_map_update_elem(map_fd, &op_idx, (uint32_t []) {0}, BPF_ANY);
        if (ret < 0) {
            fprintf(stderr, "ERR: disable option (%d/%s) failed\n", op_idx, name_ar[op_idx]);
        } else {
            printf(" - Disable option (%s)\n", name_ar[op_idx]);
        }
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

char *get_pin_path(char *sub_dir) {
    static char pin_dir[PIN_PATH_MAX] = {0};
    int len;

    if (pin_dir[0] == '\0') {
        len = snprintf(pin_dir, sizeof(pin_dir), "%s/%s", PIN_BASE_PATH, sub_dir);
        if (len < 0) {
            fprintf(stderr, "ERR: creating pin dirname\n");
            return NULL;
        }
    }

    return pin_dir;
}

char *get_map_path(char *sub_dir, char *map_name) {
    static char map_path[PIN_PATH_MAX] = {0};
    int len;

    len = snprintf(map_path, sizeof(map_path), "%s/%s/%s",
                PIN_BASE_PATH, sub_dir, map_name);
    if (len < 0) {
        fprintf(stderr, "ERR: creating map path failed (%s)\n", map_name);
        return NULL;
    }

    return map_path;
}

/* Pinning maps under /sys/fs/bpf in subdir */
int pin_maps_in_bpf_object(struct bpf_object *bpf_obj, char *subdir, int is_pin) {
    char *map_path_p;
    char *pin_dir_p;
    int err;

    pin_dir_p = get_pin_path(subdir);
    if (NULL == pin_dir_p)
        return -1;

    if (is_pin != 0) {
        map_path_p = get_map_path(subdir, xstr(TBL_NAME_OPT));
        if (NULL == map_path_p)
            return -1;


        /* Existing/previous XDP prog might not have cleaned up */
        if (access(map_path_p, F_OK ) != -1 ) {
            printf(" - Unpinning (remove) prev maps in %s/\n", pin_dir_p);

            /* Basically calls unlink(3) on map_filename */
            err = bpf_object__unpin_maps(bpf_obj, pin_dir_p);
            if (err) {
                fprintf(stderr, "ERR: UNpinning maps in %s\n", pin_dir_p);
                return -1;
            }
        }


        printf(" - Pinning maps in %s/\n", pin_dir_p);

        /* This will pin all maps in our bpf_object */
        err = bpf_object__pin_maps(bpf_obj, pin_dir_p);
        if (err) {
            fprintf(stderr, "try to mount bpf fs first ! (mount -t bpf bpf /sys/fs/bpf/)\n");
            return -1;
        }
    } else {
        printf(" - Unpinning maps in %s/\n", pin_dir_p);

        err = bpf_object__unpin_maps(bpf_obj, pin_dir_p);
        if (err) {
            fprintf(stderr, "ERR: UNpinning maps in %s\n", pin_dir_p);
            return -1;
        }
    }

    return 0;
}

int access_pinned_map (char *sub_dir_p, char *map_name_p) {

    char *map_path_p;
    int map_fd, err;
    struct bpf_map_info map_expect = { 0 };
    struct bpf_map_info info = { 0 };

    map_path_p = get_map_path(sub_dir_p, map_name_p);
    if (NULL == map_path_p)
        return -1;

    map_fd = open_bpf_map_file(map_path_p, &info);
    if (map_fd < 0) {
        return -1;
    }

    /* check map info, e.g. datarec is expected size */
    map_expect.key_size    = sizeof(uint32_t);
    map_expect.value_size  = sizeof(uint32_t);
    map_expect.max_entries = OP_MAX;
    err = check_map_fd_info(&info, &map_expect);
    if (err) {
        fprintf(stderr, "ERR: map via FD not compatible\n");
        return -1;
    }

    return map_fd;
}

void update_options (int map_fd) {
    int idx, opt_idx;

    if (map_fd <= 0)
        return;

    for (idx =0; idx <user_arguments.en_num; idx ++) {
        opt_idx = strtoul(user_arguments.en_opt_p[idx], NULL, 0);
        if (errno != 0) {
            continue;
        }

        enable_opt(map_fd, opt_idx, 1);
    }

    for (idx =0; idx <user_arguments.dis_num; idx ++) {
        opt_idx = strtoul(user_arguments.dis_opt_p[idx], NULL, 0);
        if (errno != 0) {
            continue;
        }

        enable_opt(map_fd, opt_idx, 0);
    }
}

int main(int argc, char **argv) {
    char *prog_name_p;
        char kern_prog_name[256]; //basename, ex: xxx
    char kern_prog_path[256]; //including path, ex yyy/yyy/xxx
    int main_fd, err, fd, cb_tbl_fd, cnt_tbl_fd, opt_tbl_fd;
    struct bpf_program *prog;
    struct bpf_object *obj;

    /* Our argp parser. */
    static struct argp argp = { user_options, user_parse_opt, NULL, NULL };
    /* Parse our arguments; every option seen by `parse_opt' will be
     * reflected inarguments.
     */
    argp_parse(&argp, argc, argv, 0, 0, &user_arguments);

    prog_name_p = basename(argv[0]);
    if (NULL == prog_name_p) {
        fprintf(stderr, "ERR: failed to get program name(%s)\n", argv[0]);
        return -1;
    }

    // only access pin map to show info or en/dis-able options.
    if (user_arguments.if_idx == 0) {
        opt_tbl_fd = access_pinned_map(prog_name_p, xstr(TBL_NAME_OPT));
        update_options(opt_tbl_fd);
        return 0;
    }

    snprintf(kern_prog_name, sizeof(kern_prog_name), "%s_kern.o", prog_name_p);
    if (NULL == get_kern_prog_path(kern_prog_path, sizeof(kern_prog_path), kern_prog_name)) {
        fprintf(stderr, "ERR: failed to get path of BPF-OBJ file(%s)\n",
            kern_prog_name);
        return -1;
    }

    obj = bpf_object__open_file(kern_prog_path, NULL);
    if (libbpf_get_error(obj)) {
        fprintf(stderr, "ERR: opening BPF object file failed\n");
        return -1;
    }

    /* load BPF program */
    if (bpf_object__load(obj)) {
        fprintf(stderr, "ERR: loading BPF object file failed\n");
        return -1;
    }

    cb_tbl_fd = bpf_object__find_map_fd_by_name(obj, xstr(TBL_NAME_CB));
    if (cb_tbl_fd < 0) {
        fprintf(stderr, "ERR: finding %s in obj file failed\n", xstr(TBL_NAME_CB));
        return -1;
    }

    cnt_tbl_fd = bpf_object__find_map_fd_by_name(obj, xstr(TBL_NAME_CNT));
    if (cnt_tbl_fd < 0) {
        fprintf(stderr, "ERR: finding %s in obj file failed\n", xstr(TBL_NAME_CNT));
        return -1;
    }

    opt_tbl_fd = bpf_object__find_map_fd_by_name(obj, xstr(TBL_NAME_OPT));
    if (opt_tbl_fd < 0) {
        fprintf(stderr, "ERR: finding %s in obj file failed\n", xstr(TBL_NAME_OPT));
        return -1;
    }

    if (user_arguments.dbg_lvl > 0) {
        enable_opt(opt_tbl_fd, OP_DBG, 1);
    }

    // default enable VXLAN/GRE/GTP/GENEVE
    enable_opt(opt_tbl_fd, OP_VXLAN, 1);
    enable_opt(opt_tbl_fd, OP_GTP, 1);
    enable_opt(opt_tbl_fd, OP_GRE, 1);
    enable_opt(opt_tbl_fd, OP_GENEVE, 1);

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

    /* Use the command name as subdir for exporting/pinning maps */
    err = pin_maps_in_bpf_object(obj, prog_name_p, 1);
    if (err) {
        fprintf(stderr, "ERR: pinning maps\n");
        return err;
    }

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

    pin_maps_in_bpf_object(obj, prog_name_p, 0);

    /* Detach XDP from interface */
    if ((err = bpf_set_link_xdp_fd(user_arguments.if_idx, -1, XDP_FLAGS_UPDATE_IF_NOEXIST)) < 0) {
        fprintf(stderr, "ERR: link set xdp unload failed (err=%d):%s\n",
            err, strerror(-err));
        return err;
    }

    printf("Done\n");
    return 0;
}
