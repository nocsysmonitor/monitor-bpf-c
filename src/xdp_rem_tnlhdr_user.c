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
#include <xdp/libxdp.h>

#include "xdp_util_user.h"
#include "xdp_util_comm.h"
#include "xdp_rem_tnlhdr_def.h"

#define en_help         "The idx of option to enable. (" xstr(0) "~" \
                          xstr(5) ")."
#define dis_help        "The idx of option to disable. (" xstr(0) "~" \
                          xstr(5) ")."
#define pri_help        "Specify the priority of the XDP program. " \
                        "Default is 10 for this program, smaller number" \
                        " runs first."
#define DEFAULT_XDP_PRIORITY	10

/* DATA TYPE DECLARATIONS
 */
typedef struct {
    char    *en_opt_p[OP_MAX];
    char    *dis_opt_p[OP_MAX];

    int     if_idx;
    int     en_num;
    int     dis_num;
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
    .en_num  = 0,
    .dis_num = 0,
    .lst_info= 0,
    .detach  = 0,
    .if_idx  = -1,
    .priority= DEFAULT_XDP_PRIORITY,
};

static struct argp_option user_options[] = {
    { 0,0,0,0, "Optional:", 7 },
    { "en",      'e', "idx",       0, en_help,     0 },
    { "dis",     'd', "idx",       0, dis_help,    0 },
    { "list",    'l', 0, 0,           lst_help,    0 },
    { 0,         'u', 0, 0,           det_help,    0 },
    { 0,         'p', "priority", 0,  pri_help,    0 },
    {0}
};

static char *opt_name_ar [] = {
        [OP_DBG]    = "DBG",
        [OP_VXLAN]  = "VXLAN",
        [OP_GTP]    = "GTP",
        [OP_GRE]    = "GRE",
        [OP_GENEVE] = "GENEVE",
};

static char *cnt_name_ar [] = {
        [CNT_VXLAN]  = "VXLAN",
        [CNT_GTP]    = "GTP",
        [CNT_GRE]    = "GRE",
        [CNT_GENEVE] = "GENEVE",
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
    case 'l':
        arguments_p->lst_info = 1;
        break;

    case 'e':
        arguments_p->en_opt_p[arguments_p->en_num++] = arg;
        break;

    case 'd':
        arguments_p->dis_opt_p[arguments_p->dis_num++] = arg;
        break;

    case 'u':
        arguments_p->detach = 1;
        break;

    case 'p':
        errno = 0;
        arguments_p->priority = strtoul(arg, NULL, 0);
        if (errno != 0) {
            argp_error(state, "Invalid priority \"%s\"", arg);
            return errno;
        }
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

static void enable_opt(int map_fd, uint32_t op_idx, int is_en) {
    int ret;

    if (is_en) {
        ret = bpf_map_update_elem(map_fd, &op_idx, (uint32_t []) {1}, BPF_ANY);
        if (ret < 0) {
            fprintf(stderr, "ERR: enable option (%d/%s) failed\n", op_idx, opt_name_ar[op_idx]);
        } else {
            printf(" - Enable option (%s)\n", opt_name_ar[op_idx]);
        }

    } else {
        ret = bpf_map_update_elem(map_fd, &op_idx, (uint32_t []) {0}, BPF_ANY);
        if (ret < 0) {
            fprintf(stderr, "ERR: disable option (%d/%s) failed\n", op_idx, opt_name_ar[op_idx]);
        } else {
            printf(" - Disable option (%s)\n", opt_name_ar[op_idx]);
        }
    }
}

static void update_options (int map_fd) {
    int idx, opt_idx;

    if (map_fd <= 0)
        return;

    for (idx =0; idx <user_arguments.en_num; idx ++) {
        errno = 0;
        opt_idx = strtoul(user_arguments.en_opt_p[idx], NULL, 0);
        if (errno != 0) {
            continue;
        }

        enable_opt(map_fd, opt_idx, 1);
    }

    for (idx =0; idx <user_arguments.dis_num; idx ++) {
        errno = 0;
        opt_idx = strtoul(user_arguments.dis_opt_p[idx], NULL, 0);
        if (errno != 0) {
            continue;
        }

        enable_opt(map_fd, opt_idx, 0);
    }
}

static void list_info(int opt_map_fd, int cnt_map_fd) {
    char *ok_fmt_str = "\tIdx/Name/Value - %02x/%6s/%08x\n";
    char *er_fmt_str = "\tIdx/Name/Value - %02x/%6s/ERR\n";
    char *ok_fmt_str_cnt = "\tIdx/Name/Value - %02x/%6s/%08jx\n";
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
        for (idx =0; idx <CNT_MAX; idx++) {
            err = bpf_map_lookup_elem(cnt_map_fd, &idx, &cnt_val);
            if (err) {
                printf(er_fmt_str, idx, cnt_name_ar[idx]);
                continue;
            }
            printf(ok_fmt_str_cnt, idx, cnt_name_ar[idx], cnt_val);
        }
        printf("\n");
    }
}

static void process_user_options(
    arguments_t *arg_p, char *prog_name_p, struct bpf_object *obj_p) {

    int cnt_map_fd, opt_map_fd;

    if (NULL != obj_p) {
        // need to load kernel program, use obj_p to access map
        cnt_map_fd = access_bpf_kern_map(obj_p, xstr(TBL_NAME_CNT));
        opt_map_fd = access_bpf_kern_map(obj_p, xstr(TBL_NAME_OPT));
    } else {
        // use prog_name_p to access pinned ma
        cnt_map_fd = access_pinned_map(prog_name_p, xstr(TBL_NAME_CNT), NULL);
        opt_map_fd = access_pinned_map(prog_name_p, xstr(TBL_NAME_OPT), NULL);
    }

    // default enable VXLAN/GRE/GTP/GENEVE
    enable_opt(opt_map_fd, OP_VXLAN, 1);
    enable_opt(opt_map_fd, OP_GTP, 1);
    enable_opt(opt_map_fd, OP_GRE, 1);
    enable_opt(opt_map_fd, OP_GENEVE, 1);

    update_options(opt_map_fd);

    if (arg_p->lst_info > 0) {
        list_info(opt_map_fd, cnt_map_fd);
    }
}

int main(int argc, char **argv) {
    char *prog_name_p;
    char kern_prog_name[256]; //basename, ex: xxx
    char kern_prog_path[256]; //including path, ex yyy/yyy/xxx
    int err;
    struct bpf_object *obj;
    struct xdp_program *prog;

    /* Our argp parser. */
    static struct argp argp = { user_options, user_parse_opt, args_doc, prog_doc };
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

    /* Keep going */
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);
    printf("Press ctrl+c to exit and unload BPF\n");
    while(keep_running) {
        usleep(1000000); // 1 sec
    }
    printf("Stopped, start to unload BPF\n");

    pin_maps_in_bpf_object(obj, prog_name_p, NULL, 0);

    /* Detach XDP from interface */
    xdp_program__detach(prog, user_arguments.if_idx, XDP_MODE_SKB, 0);
    printf("Done\n");
    return 0;
}
