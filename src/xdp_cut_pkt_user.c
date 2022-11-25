#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <unistd.h>
#include <libgen.h>
#include <sys/resource.h>
#include <assert.h>
#include <net/if.h>
#include <linux/if_link.h> /* depend on kernel-headers installed */
#include <arpa/inet.h>

#include <argp.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "xdp_util_user.h"
#include "xdp_util_comm.h"
#include "xdp_cut_pkt_def.h"

#define en_sip_help     "Add source ipv4 address to filter list."
#define dis_sip_help    "Remove source ipv4 address from filter list."

/* DATA TYPE DECLARATIONS
 */
typedef struct {
    char    *en_sip_p[MAX_NBR_SIP_TBL];
    char    *dis_sip_p[MAX_NBR_SIP_TBL];

    int     dbg_lvl;
    int     if_idx;
    int     en_sip_num;
    int     dis_sip_num;
    int     lst_info;
    int     detach;
} arguments_t;


/* STATIC VARIABLE DEFINITIONS
 */
static arguments_t user_arguments = {
    .en_sip_num  = 0,
    .dis_sip_num = 0,
    .lst_info    = 0,
    .detach      = 0,
    .if_idx      = -1,
};

static struct argp_option user_options[] = {
    { 0,0,0,0, "Optional:",                                7 },
    { 0,       'e', "ip4 address", 0, en_sip_help,         0 },
    { 0,       'd', "ip4 address", 0, dis_sip_help,        0 },
    { 0,       'l', 0, 0,             lst_help,            0 },
    { 0,       'u', 0, 0,             det_help,            0 },
    { 0}
};

/* Parse a single option. */
static error_t
user_parse_opt(int key, char *arg, struct argp_state *state)
{
    /* Get the input argument from argp_parse, which we
       know is a pointer to our arguments structure. */
    arguments_t *arguments_p = state->input;

    switch (key)
    {
    case 'e':
        if (arguments_p->en_sip_num >= MAX_NBR_SIP_TBL) {
            argp_error(state, "Too many SIPs to add \"%s\"", arg);
            return -1;
        }
        arguments_p->en_sip_p[arguments_p->en_sip_num++] = arg;
        break;

    case 'd':
        if (arguments_p->dis_sip_num >= MAX_NBR_SIP_TBL) {
            argp_error(state, "Too many SIPs to remove \"%s\"", arg);
            return -1;
        }
        arguments_p->dis_sip_p[arguments_p->dis_sip_num++] = arg;
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
            if (arguments_p->en_sip_num == 0 &&
                arguments_p->dis_sip_num == 0 &&
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

static volatile sig_atomic_t keep_running = 1;

static void sig_handler(int _) {
    (void)_;
    keep_running = 0;
}

static int xdp_link_detach(int ifindex, __u32 xdp_flags) {
    int err;

    if ((err = bpf_set_link_xdp_fd(ifindex, -1, xdp_flags)) < 0) {
        fprintf(stderr, "ERR: link set xdp unload failed (err=%d):%s\n",
            err, strerror(-err));
        return err;
    }
    return 0;
}

static void update_filter_sip(int map_fd) {
    int     idx;
    struct in_addr netAddr;

    /* Add SIPs to filter map */
    for (idx = 0; idx < user_arguments.en_sip_num; idx++) {
        //inet_addr: network order
        netAddr.s_addr = inet_addr(user_arguments.en_sip_p[idx]);
        bpf_map_update_elem(map_fd, &netAddr.s_addr, (uint32_t []) {1}, BPF_ANY);
    }

    /* Remove SIPs from filter map */
    for (idx = 0; idx < user_arguments.dis_sip_num; idx++) {
        netAddr.s_addr = inet_addr(user_arguments.dis_sip_p[idx]);
        bpf_map_delete_elem(map_fd, &netAddr.s_addr);
    }
}

static void update_en_sip_filter(int en_map_fd, int sip_map_fd) {
    uint32_t *cur_key = NULL;
    uint32_t next_key;
    uint32_t value =1;
    int err;

    err = bpf_map_get_next_key(sip_map_fd, cur_key, &next_key);
    if (err) {
        value = 0;
    }

    bpf_map_update_elem(en_map_fd, (uint32_t []) {0}, &value, BPF_ANY);
}

static void list_filter_sip(int map_fd) {
    uint32_t *cur_key = NULL;
    uint32_t next_key;
    unsigned char *byte_p = (unsigned char *)&next_key;
    int err;

    printf("SIP Filter List:\n");
    for (;;) {
        err = bpf_map_get_next_key(map_fd, cur_key, &next_key);
        if (err) {
            break;
        }

        printf(" - %d.%d.%d.%d\n",
            byte_p[0], byte_p[1], byte_p[2], byte_p[3]);

        cur_key = &next_key;
    }

    if (NULL == cur_key) {
        printf(" - Empty\n");
    }
    printf("\n");
}

static void list_info(int cnt_map_fd, int sip_map_fd, int ensip_map_fd) {
    char *ok_fmt_str = "\tIdx/Name/Value - %02x/%8s/%08x\n";
    char *er_fmt_str = "\tIdx/Name/Value - %02x/%8s/ERR\n";
    char *ok_fmt_str_cnt = "\tIdx/Name/Value - %02x/%8s/%08jx\n";
    uint32_t idx =0, value;
    uint64_t cnt_val;
    int err;

    printf("\n");
    if (ensip_map_fd > 0) {
        //option info
        printf("Option Info:\n");
        err = bpf_map_lookup_elem(ensip_map_fd, &idx, &value);
        if (err) {
            printf(er_fmt_str, idx, "SIP FILT");
        } else {
            printf(ok_fmt_str, idx, "SIP FILT", value);
        }
        printf("\n");
    }

    if (cnt_map_fd > 0) {
        printf("Counter Info:\n");
        //counter info
        err = bpf_map_lookup_elem(cnt_map_fd, &idx, &cnt_val);
        if (err) {
            printf(er_fmt_str, idx, "MODIFIED");
        } else {
            printf(ok_fmt_str_cnt, idx, "MODIFIED", cnt_val);
        }
        printf("\n");
    }

    if (sip_map_fd > 0) {
        list_filter_sip(sip_map_fd);
    }
}

static void process_user_options(
    arguments_t *arg_p, char *prog_name_p, struct bpf_object *obj_p) {

    int cnt_map_fd, sip_map_fd, ensip_map_fd;

    if (NULL != obj_p) {
        // need to load kernel program, use obj_p to access map
        cnt_map_fd = access_bpf_kern_map(obj_p, xstr(TBL_NAME_CNT));
        sip_map_fd = access_bpf_kern_map(obj_p, xstr(TBL_NAME_SIP));
        ensip_map_fd = access_bpf_kern_map(obj_p, xstr(TBL_NAME_EN_SIP));
    } else {
        // use prog_name_p to access pinned ma
        cnt_map_fd = access_pinned_map(prog_name_p, xstr(TBL_NAME_CNT), NULL);
        sip_map_fd = access_pinned_map(prog_name_p, xstr(TBL_NAME_SIP), NULL);
        ensip_map_fd = access_pinned_map(prog_name_p, xstr(TBL_NAME_EN_SIP), NULL);
    }

    update_filter_sip(sip_map_fd);
    update_en_sip_filter(ensip_map_fd, sip_map_fd);

    if (arg_p->lst_info > 0) {
        list_info(cnt_map_fd, sip_map_fd, ensip_map_fd);
    }
}

int main(int argc, char **argv) {
    char *prog_name_p;
    char kern_prog_name[256]; //basename, ex: xxx
    char kern_prog_path[256]; //including path, ex yyy/yyy/xxx
    struct rlimit r = {RLIM_INFINITY, RLIM_INFINITY};
    int progFd, err;
    struct bpf_object *obj;

    /* Our argp parser. */
    static struct argp argp = { user_options, user_parse_opt, args_doc, prog_doc };

    /* Parse our arguments; every option seen by `parse_opt' will be
     * reflected in arguments.
     */
    argp_parse(&argp, argc, argv, 0, 0, &user_arguments);

    /* Set resource limit for maps */
    if (setrlimit(RLIMIT_MEMLOCK, &r)) {
        perror("setrlimit(RLIMIT_MEMLOCK)");
        return -1;
    }

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

    // detach program first
    if (user_arguments.detach) {
        /* Detach XDP from interface */
        if ((err = bpf_set_link_xdp_fd(
                    user_arguments.if_idx, -1, XDP_FLAGS_UPDATE_IF_NOEXIST)) < 0) {
            fprintf(stderr, "ERR: link set xdp unload failed (err=%d):%s\n",
                    err, strerror(-err));
            return err;
        }
    }

    snprintf(kern_prog_name, sizeof(kern_prog_name), "%s_kern.o", prog_name_p);
    if (NULL == get_kern_prog_path(kern_prog_path, sizeof(kern_prog_path), kern_prog_name)) {
        fprintf(stderr, "ERR: failed to get path of BPF-OBJ file(%s)\n",
            kern_prog_name);
        return -1;
    }

    /* Load the BPF-ELF object file and get back first BPF_prog FD because we only had one */
    err = bpf_prog_load(kern_prog_path, BPF_PROG_TYPE_XDP, &obj, &progFd);
    if (err) {
        fprintf(stderr, "ERR: loading BPF-OBJ file(%s) (%d): %s\n",
            kern_prog_path, err, strerror(-err));
        return err;
    }
    printf("Program loaded with id: %d\n", progFd);

    process_user_options(&user_arguments, NULL, obj);

    /* Attach BPF program to interface */
    err = bpf_set_link_xdp_fd(user_arguments.if_idx, progFd, XDP_FLAGS_UPDATE_IF_NOEXIST);
    if (err) {
        fprintf(stderr, "ERR: ifindex(%d) link set xdp fd failed (%d): %s\n",
            user_arguments.if_idx, err, strerror(-err));
        return err;
    }
    printf("BPF attatched to interface: %d\n", user_arguments.if_idx);

    /* Use the command name as subdir for exporting/pinning maps */
    err = pin_maps_in_bpf_object(obj, prog_name_p, NULL, 1);
    if (err) {
        fprintf(stderr, "ERR: pinning maps\n");
        return err;
    }

    /* Keep going */
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);
    printf("Press ctrl+c to exit and unload BPF\n");
    while(keep_running) {
        sleep(1);
    }
    printf("Stopped, start to unload BPF\n");

    pin_maps_in_bpf_object(obj, prog_name_p, NULL, 0);

    /* Detach XDP from interface */
    xdp_link_detach(user_arguments.if_idx, XDP_FLAGS_UPDATE_IF_NOEXIST);
    printf("Done\n");
    return 0;
}
