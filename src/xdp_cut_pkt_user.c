#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <unistd.h>
#include <sys/resource.h>
#include <assert.h>
#include <net/if.h>
#include <linux/if_link.h> /* depend on kernel-headers installed */
#include <arpa/inet.h>

#include <argp.h>
#include <libgen.h>
#include "xdp_cut_pkt_def.h"

/* MACRO FUNCTION DECLARATIONS
 */
#define xstr(s) str(s)
#define str(s)  #s
#define dbglvl_help     "The verbosity of debug messages (" xstr(0) \
                          "~" xstr(3) ")."

#define inf_help        "The name of interface to use."
#define sip_help        "The source ipv4 address to filter."

/* DATA TYPE DECLARATIONS
 */
typedef struct {
    int     debuglvl;
    int     if_idx;
    char    *sip[MAX_NBR_SIP_TBL];
    int     sip_num;
} arguments_t;


/* STATIC VARIABLE DEFINITIONS
 */
static arguments_t loader_arguments = {
    .debuglvl = 0,
    .sip_num  = 0,
};

static struct argp_option loader_options[] =
{
    { "debuglvl",  'd', "DEBUGLVL",    0, dbglvl_help, 0 },
    { "inf",       'i', "interface",   0, inf_help,    0 },
    { "sip",       's', "ip4 address", 0, sip_help,    0 },
    { 0 }                                                                                           };

/* Parse a single option. */
static error_t
loader_parse_opt(int key, char *arg, struct argp_state *state)
{
    /* Get the input argument from argp_parse, which we
       know is a pointer to our arguments structure. */
    arguments_t *arguments_p = state->input;

    switch (key)
    {
    case 'd':
        errno = 0;

        arguments_p->debuglvl = strtoul(arg, NULL, 0);
        if (errno != 0) {
            argp_error(state, "Invalid debuglvl \"%s\"", arg);
            return errno;
        }
        break;

    case 's':
        arguments_p->sip[arguments_p->sip_num++] = arg;
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

static char *get_prog_path(char *buffer_p, int size) {
    char buf[1024] = {0};

    /* Note we use sizeof(buf)-1 since we may need an extra char for NUL. */
    if (readlink("/proc/self/exe", buf, sizeof(buf)-1) < 0) {
        /* There was an error...  Perhaps the path does not exist
         * or the buffer is not big enough.  errno has the details. */
        perror("readlink");
        return NULL;
    }

    snprintf(buffer_p, size, "%s/%s", dirname(buf), KERN_PROG_NAME);
    return buffer_p;
}

static volatile sig_atomic_t keep_running = 1;

static void sig_handler(int _) {
    (void)_;
    keep_running = 0;
}


void add_filter_host(int mapFd, uint32_t *sip) {
    int one = 1;
    bpf_map_update_elem(mapFd, sip, &one, BPF_ANY);
}

void del_filter_host(int mapFd, uint32_t *sip) {
    bpf_map_delete_elem(mapFd, sip);
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


int main(int argc, char **argv) {
    char filename[256]; // = "./prog_cut_pkt.o";
    //#char *sip_array[] = {"192.168.200.14", "192.168.200.15", "7.5.5.6"};

    struct rlimit r = {RLIM_INFINITY, RLIM_INFINITY};
    int progFd, en_sip_filter_map_fd, sip_filter_map_fd, mod_total_map_fd, err;
    int index = 0;
    struct bpf_object *obj;
    struct bpf_map *map;
    uint64_t value;
    struct in_addr netAddr;

    /* Our argp parser. */
    static struct argp argp = { loader_options, loader_parse_opt, NULL, NULL };

    /* Parse our arguments; every option seen by `parse_opt' will be
     * reflected in arguments.
     */
    argp_parse(&argp, argc, argv, 0, 0, &loader_arguments);

    /* Set resource limit for maps */
    if (setrlimit(RLIMIT_MEMLOCK, &r)) {
        perror("setrlimit(RLIMIT_MEMLOCK)");
        return -1;
    }

    if (NULL == get_prog_path(filename, sizeof(filename))) {
        fprintf(stderr, "ERR: failed to get path of BPF-OBJ file(%s)\n",
            KERN_PROG_NAME);
        return -1;
    }

    /* Load the BPF-ELF object file and get back first BPF_prog FD because we only had one */
    err = bpf_prog_load(filename, BPF_PROG_TYPE_XDP, &obj, &progFd);
    if (err) {
        fprintf(stderr, "ERR: loading BPF-OBJ file(%s) (%d): %s\n",
            filename, err, strerror(-err));
        return err;
    }
    printf("Program loaded with id: %d\n", progFd);

    /* Get maps */
    en_sip_filter_map_fd = get_map(obj, "en_sip_filter");
    if (en_sip_filter_map_fd < 0) {
        fprintf(stderr, "ERR: get map of %s failed.\n", "en_sip_filter");
        return en_sip_filter_map_fd;
    }

    sip_filter_map_fd = get_map(obj, "sip_filter");
    if (sip_filter_map_fd < 0) {
        fprintf(stderr, "ERR: get map of %s failed.\n", "sip_filter");
        return sip_filter_map_fd;
    }

    mod_total_map_fd = get_map(obj, "mod_total");
    if (mod_total_map_fd < 0) {
        fprintf(stderr, "ERR: get map of %s failed.\n", "mod_total");
        return mod_total_map_fd;
    }

    /* Add SIP to filter map */
    for (int idx = 0; idx < loader_arguments.sip_num; idx++) {
        netAddr.s_addr = inet_addr(loader_arguments.sip[idx]);
        add_filter_host(sip_filter_map_fd, &netAddr.s_addr);
    }

    /* Attach BPF program to interface */
    err = bpf_set_link_xdp_fd(loader_arguments.if_idx, progFd, XDP_FLAGS_UPDATE_IF_NOEXIST);
    if (err) {
        fprintf(stderr, "ERR: ifindex(%d) link set xdp fd failed (%d): %s\n",
            loader_arguments.if_idx, err, strerror(-err));
        return err;
    }
    printf("BPF attatched to interface: %d\n", loader_arguments.if_idx);

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

    /* Detach XDP from interface */
    xdp_link_detach(loader_arguments.if_idx, XDP_FLAGS_UPDATE_IF_NOEXIST);
    printf("Done\n");
    return 0;
}

