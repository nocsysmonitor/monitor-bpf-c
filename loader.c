#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <sys/resource.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include <net/if.h>
#include <linux/if_link.h> /* depend on kernel-headers installed */

#include <argp.h>


/* MACRO FUNCTION DECLARATIONS
 */
#define xstr(s) str(s)
#define str(s)  #s
#define dbglvl_help     "The verbosity of debug messages (" xstr(0) \
                          "~" xstr(3) ")."

#define inf_help        "The name of interface to use."

/* DATA TYPE DECLARATIONS
 */
typedef struct {
    int     debuglvl;
    int     if_idx;
} arguments_t;


/* STATIC VARIABLE DEFINITIONS
 */
static arguments_t loader_arguments = {
    .debuglvl = 0,
};

static struct argp_option loader_options[] =
{
    { "debuglvl", 'd', "DEBUGLVL",  0, dbglvl_help, 0 },
    { "inf",      'i', "interface", 0, inf_help,    0 },
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

    default:
        return ARGP_ERR_UNKNOWN;
    }

    return 0;
}

static volatile sig_atomic_t keep_running = 1;

static void sig_handler(int _)
{
	(void)_;
	keep_running = 0;
}

int load_bpf_object_file__simple(const char *filename)
{
	int first_prog_fd = -1;
	struct bpf_object *obj;
	int err;

	/* Use libbpf for extracting BPF byte-code from BPF-ELF object, and
	 * loading this into the kernel via bpf-syscall
	 */
	err = bpf_prog_load(filename, BPF_PROG_TYPE_XDP, &obj, &first_prog_fd);
	if (err) {
		fprintf(stderr, "ERR: loading BPF-OBJ file(%s) (%d): %s\n",
			filename, err, strerror(-err));
		return -1;
	}

	/* Simply return the first program file descriptor.
	 * (Hint: This will get more advanced later)
	 */
	return first_prog_fd;
}

int xdp_link_attach(int ifindex, __u32 xdp_flags, int prog_fd)
{
	/* Next assignment this will move into ../common/ */
	int err;

	/* libbpf provide the XDP net_device link-level hook attach helper */
	err = bpf_set_link_xdp_fd(ifindex, prog_fd, xdp_flags);
	if (err == -EEXIST && !(xdp_flags & XDP_FLAGS_UPDATE_IF_NOEXIST)) {
		/* Force mode didn't work, probably because a program of the
		 * opposite type is loaded. Let's unload that and try loading
		 * again.
		 */

		__u32 old_flags = xdp_flags;

		xdp_flags &= ~XDP_FLAGS_MODES;
		xdp_flags |= (old_flags & XDP_FLAGS_SKB_MODE) ? XDP_FLAGS_DRV_MODE : XDP_FLAGS_SKB_MODE;
		err = bpf_set_link_xdp_fd(ifindex, -1, xdp_flags);
		if (!err)
			err = bpf_set_link_xdp_fd(ifindex, prog_fd, old_flags);
	}

	if (err < 0) {
		fprintf(stderr, "ERR: "
			"ifindex(%d) link set xdp fd failed (%d): %s\n",
			ifindex, -err, strerror(-err));

		switch (-err) {
		case EBUSY:
		case EEXIST:
			fprintf(stderr, "Hint: XDP already loaded on device"
				" use --force to swap/replace\n");
			break;
		case EOPNOTSUPP:
			fprintf(stderr, "Hint: Native-XDP not supported"
				" use --skb-mode or --auto-mode\n");
			break;
		default:
			break;
		}
		return -1;
	}

	return 0;
}

static int xdp_link_detach(int ifindex, __u32 xdp_flags)
{
	/* Next assignment this will move into ../common/
	 * (in more generic version)
	 */
	int err;

	if ((err = bpf_set_link_xdp_fd(ifindex, -1, xdp_flags)) < 0) {
		fprintf(stderr, "ERR: link set xdp unload failed (err=%d):%s\n",
			err, strerror(-err));
		return -1;
	}
	return 0;
}

int main(int argc, char **argv) {
    struct rlimit r = {RLIM_INFINITY, RLIM_INFINITY};
    char filename[256] = "program.o";
//	int ifIndex = 3; // ip link show
	int prog_fd, err;

    /* Our argp parser. */
    static struct argp argp = { loader_options, loader_parse_opt, NULL, NULL };

    /* Parse our arguments; every option seen by `parse_opt' will be
     * reflected in arguments.
     */
    argp_parse(&argp, argc, argv, 0, 0, &loader_arguments);

    if (setrlimit(RLIMIT_MEMLOCK, &r)) {
        perror("setrlimit(RLIMIT_MEMLOCK)");
        return -1;
    }

	/* Load the BPF-ELF object file and get back first BPF_prog FD */
	prog_fd = load_bpf_object_file__simple(filename);
	if (prog_fd <= 0) {
		fprintf(stderr, "ERR: loading file: %s\n", filename);
		return -1;
	}
	printf("Program loaded with id: %d\n", prog_fd);

	/* Attach XDP to interface  */
	err = xdp_link_attach(loader_arguments.if_idx, XDP_FLAGS_UPDATE_IF_NOEXIST, prog_fd);
	if (err)
		return err;
	printf("XDP attatched to %d interface\n", loader_arguments.if_idx);

	/* Keep going */
	signal(SIGINT, sig_handler);
	printf("Ctrl+c to exit and unload BPF\n");
	while(keep_running) {
	}
	printf("Stopped, start to unload BPF\n");

	/* Detach XDP from interface */
	xdp_link_detach(loader_arguments.if_idx, XDP_FLAGS_UPDATE_IF_NOEXIST);
	printf("Done\n");
}
