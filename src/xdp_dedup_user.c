#include <getopt.h>
#include <signal.h>
#include <net/if.h>
#include <unistd.h>
#include <stdbool.h>
#include <libgen.h>
#include <linux/if_link.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <signal.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <xdp/libxdp.h>
#include <argp.h>

#include "xdp_util_user.h"
#include "xdp_util_comm.h"
#include "xdp_dedup_def.h"


#define dbg_help        "Enable kernel debug messages (0/1 : dis/en)."

#define per_help        "Period of time to clear hash table." \
                        "(in us, effect only when loading kernel program)."
#define len_help        "Length of payload for calculating hash key" \
                        "(in bytes, set 0 to use whole packet," \
                        " limit: " xstr(LOOP_MAX_LEN_) ")."
#define pri_help	"Specify the priority of the XDP program. " \
	                "Default is 20 for this program, smaller number" \
			" runs first."
#define DEFAULT_XDP_PRIORITY	20

/* DATA TYPE DECLARATIONS
 */
typedef struct {
    int     dbg_lvl;
    int     if_idx;
    int     period;
    int     hlen;
    int     lst_info;
    int     detach;
    int     priority;
} arguments_t;

typedef struct {
    char    *name_p;
    int     cb_idx;
} prog_ele_t;

/* STATIC VARIABLE DEFINITIONS
 */
static arguments_t user_arguments = {
    .dbg_lvl = 0,
    .if_idx  = -1,
    .hlen    = -1,
    .priority= DEFAULT_XDP_PRIORITY,
};

static struct argp_option user_options[] = {
    { 0,0,0,0, "Optional:",                                7 },
    { 0,         'd', "lvl", 0,       dbg_help,            0 },
    { 0,         'l', 0, 0,           lst_help,            0 },
    { 0,         'u', 0, 0,           det_help,            0 },
    { 0,         't', "us", 0,        per_help,            0 },
    { 0,         'h', "bytes", 0,     len_help,            0 },
    { 0,         'p', "priority", 0,  pri_help,            0 },
    { 0}
};

static char *opt_name_ar [] = {
        [OP_DBG]    = "DBG",
        [OP_HLEN]   = "HASH LEN",
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

    case 't':
        errno = 0;
        arguments_p->period = strtoul(arg, NULL, 0);
        if (errno != 0) {
            argp_error(state, "Invalid period \"%s\"", arg);
            return errno;
        }
        break;

    case 'h':
        errno = 0;
        arguments_p->hlen = strtoul(arg, NULL, 0);
        if (errno != 0) {
            argp_error(state, "Invalid length \"%s\"", arg);
            return errno;
        }
        break;

    case 'p':
        errno = 0;
        arguments_p->priority = strtoul(arg, NULL, 0);
        if (errno != 0) {
            argp_error(state, "Invalid priority \"%s\"", arg);
            return errno;
        }
        break;

    case 'l':
        arguments_p->lst_info = 1;
        break;

    case 'u':
        arguments_p->detach = 1;
        break;

    case ARGP_KEY_ARG:
        /* Too many arguments. */
        // for arguments, not for options above.
        if (state->arg_num > 1)
            argp_usage (state);

        arguments_p->if_idx = if_nametoindex(arg);
        if (errno != 0) {
            argp_error(state, "Invalid interface name \"%s\"", arg);
            return errno;
        }
        break;

    case ARGP_KEY_END:
        if (arguments_p->if_idx == -1) {
           if (arguments_p->hlen == -1 &&
               arguments_p->lst_info == 0) {

                argp_failure(state, 1, 0, "interface is required. See --help for more information");
                exit(ARGP_ERR_UNKNOWN);
            }
        }

    default:
        return ARGP_ERR_UNKNOWN;
    }

    return 0;
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

        if (value != 0) {
            bpf_map_update_elem(map_fd, &next_key, (uint32_t []) {0}, BPF_ANY);

            if (cnt % 10 == 0)
                printf("reset key/value - %08x/%08x\n", next_key, value);
        }

        cur_key = &next_key;
    }
}

static void list_info(int opt_map_fd, int cnt_map_fd) {
    char *ok_fmt_str = "\tIdx/Name/Value - %02x/%8s/%08x\n";
    char *er_fmt_str = "\tIdx/Name/Value - %02x/%8s/ERR\n";
    char *ok_fmt_str_cnt = "\tIdx/Name/Value - %02x/%8s/%08jx\n";
    uint32_t idx, value;
    uint64_t cnt_val;
    int err;

    printf("\n");
    if (opt_map_fd > 0) {
        //option info
        printf("Option Info:\n");
        for (idx =0; idx <OP_MAX; idx++) {
            err = bpf_map_lookup_elem(opt_map_fd, &idx, &value);
            if (err) {
                printf(er_fmt_str, idx, opt_name_ar[idx]);
                continue;
            }
            printf(ok_fmt_str, idx, opt_name_ar[idx], value);
        }
        printf("\n");
    }

    if (cnt_map_fd > 0) {
        printf("Counter Info:\n");
        //counter info
        idx = 0;
        err = bpf_map_lookup_elem(cnt_map_fd, &idx, &cnt_val);
        if (err) {
            printf(er_fmt_str, idx, "DROP");
        } else {
            printf(ok_fmt_str_cnt, idx, "DROP", cnt_val);
        }
        printf("\n");
    }
}

static void update_options(arguments_t *arg_p, int opt_map_fd) {

    uint32_t value;
    int ret;

    value = (arg_p->dbg_lvl > 0) ? 1 : 0;
    ret = bpf_map_update_elem(opt_map_fd, (uint32_t []) {OP_DBG}, &value, BPF_ANY);
    if (ret < 0) {
        fprintf(stderr, "ERR: set option dbg failed\n");
    }

    value = (arg_p->hlen != -1) ? arg_p->hlen : DFLT_HASH_LEN;
    ret = bpf_map_update_elem(opt_map_fd, (uint32_t []) {OP_HLEN}, &value, BPF_ANY);
    if (ret < 0) {
        fprintf(stderr, "ERR: set option hash len failed\n");
    }
}

static void process_user_options(
    arguments_t *arg_p, char *prog_name_p, struct bpf_object *obj_p) {

    int opt_map_fd, cnt_map_fd;

    if (NULL != obj_p) {
        // need to load kernel program, use obj_p to access map
        opt_map_fd = access_bpf_kern_map(obj_p, xstr(TBL_NAME_OPT));
        cnt_map_fd = access_bpf_kern_map(obj_p, xstr(TBL_NAME_DROP));
    } else {
        // use prog_name_p to access pinned ma
        opt_map_fd = access_pinned_map(prog_name_p, xstr(TBL_NAME_OPT), NULL);
        cnt_map_fd = access_pinned_map(prog_name_p, xstr(TBL_NAME_DROP), NULL);
    }

    update_options(arg_p, opt_map_fd);

    if (arg_p->lst_info > 0) {
        list_info(opt_map_fd, cnt_map_fd);
    }

    // set default period, only take effect when loading kernel program
    if (arg_p->period == 0) {
        arg_p->period = SLEEP_TIME_IN_US;
    }
}

int main(int argc, char **argv) {
    char *prog_name_p;
    char kern_prog_name[256]; //basename, ex: xxx
    char kern_prog_path[256]; //including path, ex yyy/yyy/xxx
    int err, hash_tbl_fd;
    struct bpf_object *obj;
    struct xdp_program *prog;

    /* Our argp parser. */
    static struct argp argp = { user_options, user_parse_opt, args_doc, prog_doc };

    /* Parse our arguments; every option seen by `parse_opt' will be
     * reflected in arguments.
     */
    argp_parse(&argp, argc, argv, 0, 0, &user_arguments);

    prog_name_p = basename(argv[0]);
    if (NULL == prog_name_p) {
        fprintf(stderr, "ERR: failed to get program name(%s)\n", argv[0]);
        return -1;
    }

    // only access pinned map to add/remove sips
    if (user_arguments.if_idx == -1) {
        process_user_options(&user_arguments, prog_name_p, NULL);
        return 0;
    }

    snprintf(kern_prog_name, sizeof(kern_prog_name), "%s_kern.o", prog_name_p);
    if (NULL == get_kern_prog_path(kern_prog_path, sizeof(kern_prog_path), kern_prog_name)) {
        fprintf(stderr, "ERR: failed to get path of BPF-OBJ file(%s)\n",
            kern_prog_name);
        return -1;
    }

    /* Open XDP program file and get bpf_obj from file  using LIBXDP */
    prog = xdp_program__open_file(kern_prog_name, "xdp", NULL);
    obj = xdp_program__bpf_obj(prog);
    xdp_program__set_run_prio(prog, user_arguments.priority);

    /* Attach BPF program to interface */
    silence_libbpf_logging(); // Comment this out for debugging
    err = xdp_program__attach_multi(&prog, 1, user_arguments.if_idx, XDP_MODE_SKB, 0);
    if (err) {
        fprintf(stderr, "ERR: attaching XDP program\n");
        xdp_program__detach(prog, user_arguments.if_idx, XDP_MODE_SKB, 0);
        return err;
    }
    printf("BPF attatched to interface: %d\n", user_arguments.if_idx);

    /* Use the command name as subdir for exporting/pinning maps */
    err = pin_maps_in_bpf_object(obj, prog_name_p, NULL, 1);
    if (err) {
        fprintf(stderr, "ERR: pinning maps\n");
        xdp_program__detach(prog, user_arguments.if_idx, XDP_MODE_SKB, 0);
        return err;
    }

    process_user_options(&user_arguments, prog_name_p, NULL);

    hash_tbl_fd = bpf_object__find_map_fd_by_name(obj, xstr(TBL_NAME_HASH));
    if (hash_tbl_fd < 0) {
        fprintf(stderr, "ERR: finding %s in obj file failed\n", xstr(TBL_NAME_HASH));
        xdp_program__detach(prog, user_arguments.if_idx, XDP_MODE_SKB, 0);
        return -1;
    }

    /* Keep going */
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);
    printf("Press ctrl+c to exit and unload BPF\n");
    while(keep_running) {
        // reset hash table in 500 ms (default)
        clear_hash_elements(hash_tbl_fd, 1);
        usleep(user_arguments.period);
    }
    printf("Stopped, start to unload BPF\n");

    pin_maps_in_bpf_object(obj, prog_name_p, NULL, 0);

    /* Detach XDP from interface */
    xdp_program__detach(prog, user_arguments.if_idx, XDP_MODE_SKB, 0);
    printf("Done\n");
    return 0;
}

