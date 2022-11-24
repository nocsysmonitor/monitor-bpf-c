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
#include "xdp_cut_pkt_def.h"

/* MACRO FUNCTION DECLARATIONS
 */
#define xstr(s) str(s)
#define str(s)  #s
#define dbglvl_help     "The verbosity of debug messages (" xstr(0) \
                          "~" xstr(1) ")."

#define inf_help        "The name of interface to use."
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
    int     list_sip;
} arguments_t;


/* STATIC VARIABLE DEFINITIONS
 */
static arguments_t user_arguments = {
    .dbg_lvl     = 0,
    .en_sip_num  = 0,
    .dis_sip_num = 0,
    .list_sip    = 0,
};

static struct argp_option user_options[] = {
    { 0,0,0,0, "Optional:",                                7 },
    { "dbg_lvl",   'd', "level", 0, dbglvl_help,           0 },
    { "sip",       'e', "ip4 address", 0, en_sip_help,     0 },
    { "sip",       'u', "ip4 address", 0, dis_sip_help,    0 },
    { 0,           'l', 0, 0, "List SIPs in filter table", 0 },
    { 0,0,0,0, "Required for loading xdp kernel program:", 5 },
    { "inf",       'i', "interface",   0, inf_help,        0 },
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
    case 'd':
        errno = 0;

        arguments_p->dbg_lvl = strtoul(arg, NULL, 0);
        if (errno != 0) {
            argp_error(state, "Invalid level \"%s\"", arg);
            return errno;
        }
        break;

    case 'e':
        if (arguments_p->en_sip_num >= MAX_NBR_SIP_TBL) {
            argp_error(state, "Too many SIPs to add \"%s\"", arg);
            return -1;
        }
        arguments_p->en_sip_p[arguments_p->en_sip_num++] = arg;
        break;

    case 'u':
        if (arguments_p->dis_sip_num >= MAX_NBR_SIP_TBL) {
            argp_error(state, "Too many SIPs to remove \"%s\"", arg);
            return -1;
        }
        arguments_p->dis_sip_p[arguments_p->dis_sip_num++] = arg;
        break;

    case 'l':
        arguments_p->list_sip = 1;
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
        // for arguments, not for options above.
        // we do not accept any arguments
        if (state->arg_num > 0)
            argp_usage (state);

        break;

    case ARGP_KEY_END:
        if (arguments_p->if_idx == 0) {
            if (arguments_p->en_sip_num == 0 &&
                arguments_p->dis_sip_num == 0 &&
                arguments_p->list_sip == 0) {

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

static int get_map(struct bpf_object *obj, const char *filename) {
    struct bpf_map *map;
    map = bpf_object__find_map_by_name(obj, filename);
    if (map) {
        return bpf_map__fd(map);
    }
    return -1;
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
        printf(" - Empty (sip filtering is disabled)\n");
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

int main(int argc, char **argv) {
    char *prog_name_p;
    char kern_prog_name[256]; //basename, ex: xxx
    char kern_prog_path[256]; //including path, ex yyy/yyy/xxx
    struct rlimit r = {RLIM_INFINITY, RLIM_INFINITY};
    int progFd, en_sip_filter_map_fd, sip_filter_map_fd, mod_total_map_fd, err;
    int index = 0;
    struct bpf_object *obj;
    uint64_t value;
    struct in_addr netAddr;

    /* Our argp parser. */
    static struct argp argp = { user_options, user_parse_opt, NULL, NULL };

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
    if (user_arguments.if_idx == 0) {
        sip_filter_map_fd = access_pinned_map(prog_name_p, xstr(TBL_NAME_SIP), NULL);
        update_filter_sip(sip_filter_map_fd);

        en_sip_filter_map_fd = access_pinned_map(prog_name_p, xstr(TBL_NAME_EN_SIP), NULL);

        update_en_sip_filter(en_sip_filter_map_fd, sip_filter_map_fd);

        if (user_arguments.list_sip) {
            list_filter_sip(sip_filter_map_fd);
        }
        return 0;
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

    /* Get maps */
    en_sip_filter_map_fd = get_map(obj, xstr(TBL_NAME_EN_SIP));
    if (en_sip_filter_map_fd < 0) {
        fprintf(stderr, "ERR: get map of %s failed.\n", xstr(TBL_NAME_EN_SIP));
        return en_sip_filter_map_fd;
    }

    sip_filter_map_fd = get_map(obj, xstr(TBL_NAME_SIP));
    if (sip_filter_map_fd < 0) {
        fprintf(stderr, "ERR: get map of %s failed.\n", xstr(TBL_NAME_SIP));
        return sip_filter_map_fd;
    }

    mod_total_map_fd = get_map(obj, xstr(TBL_NAME_CNT));
    if (mod_total_map_fd < 0) {
        fprintf(stderr, "ERR: get map of %s failed.\n", xstr(TBL_NAME_CNT));
        return mod_total_map_fd;
    }

    update_filter_sip(sip_filter_map_fd);
    update_en_sip_filter(en_sip_filter_map_fd, sip_filter_map_fd);

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
    printf("Ctrl+c to exit and unload BPF\n");
    while(keep_running) {
        assert(bpf_map_lookup_elem(mod_total_map_fd, &index, &value) == 0);
        printf("Modified %lu packet(s).\n", value);
        sleep(1);
    }
    printf("Stopped, start to unload BPF\n");

    pin_maps_in_bpf_object(obj, prog_name_p, NULL, 0);

    /* Detach XDP from interface */
    xdp_link_detach(user_arguments.if_idx, XDP_FLAGS_UPDATE_IF_NOEXIST);
    printf("Done\n");
    return 0;
}
