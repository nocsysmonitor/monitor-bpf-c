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

#include <libgen.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "xdp_util.h"

static int ifindex = -1;
static char ifname_buf[IF_NAMESIZE];
static char *ifname = NULL;
static bool debug = false;

/* Exit return codes */
#define EXIT_OK                 0
#define EXIT_FAIL               1
#define EXIT_FAIL_OPTION        2
#define EXIT_FAIL_XDP           3
#define EXIT_FAIL_MAP		    20

static volatile sig_atomic_t keep_running = 1;

static void sig_handler(int _) {
    (void)_;
    keep_running = 0;
}

static const struct option long_options[] = {
	{"help",	no_argument,		NULL, 'h' },
	{"dev",		required_argument,	NULL, 'd' },
	{"debug",	no_argument,		NULL, 'D' },
	{"skbmode",     no_argument,		NULL, 'S' },
	{0, 0, NULL,  0 }
};

static void usage(char *argv[])
{
	int i;
	printf(" Usage: %s (options-see-below)\n",
	       argv[0]);
	printf(" Listing options:\n");
	for (i = 0; long_options[i].name != 0; i++) {
		printf(" --%-12s", long_options[i].name);
		if (long_options[i].flag != NULL)
			printf(" flag (internal value:%d)",
			       *long_options[i].flag);
		else
			printf(" short-option: -%c",
			       long_options[i].val);
		printf("\n");
	}
	printf("\n");
}

int main(int argc, char **argv)
{
	char filename[256];
    char filepath[256];
	int longindex = 0;
	int opt, i;

	/* Corresponding map_fd[index] for jump tables aka tail calls */
	int jmp_table1 = 0;
	int jmp_table2 = 1;
	int jmp_table3 = 2;

	/*
	 * WARNING: There were an issue in bpf_load.c that caused bpf
	 * prog section order in prog_fd[] to get mixed up (if prog
	 * didn't reference a map)
	 *
	 * Corresponding prog_fd[index] for prog section tail calls.
	 */
	int prog_xdp_1 = 1;
	int prog_xdp_5 = 2;
	int prog_xdp_unrelated = 3;


    int progFd, err, fd, progs_fd, key;
    struct bpf_program *prog;
    struct bpf_object *obj;
    const char *section;

	snprintf(filename, sizeof(filename), "%s_kern.o", argv[0]);

	/* Parse commands line args */
	while ((opt = getopt_long(argc, argv, "hd:",
				  long_options, &longindex)) != -1) {
		switch (opt) {
		case 'd':
			if (strlen(optarg) >= IF_NAMESIZE) {
				fprintf(stderr, "ERR: --dev name too long\n");
				goto error;
			}
			ifname = (char *)&ifname_buf;
			strncpy(ifname, optarg, IF_NAMESIZE);
			ifindex = if_nametoindex(ifname);
			if (ifindex == 0) {
				fprintf(stderr,
					"ERR: --dev name unknown err(%d):%s\n",
					errno, strerror(errno));
				goto error;
			}
			break;
		case 'D':
			debug = true;
			break;
		case 'h':
		error:
		default:
			usage(argv);
			return EXIT_FAIL_OPTION;
		}
	}

	if (ifindex == -1) {
		fprintf(stderr, "ERR: required option --dev missing");
		usage(argv);
		return EXIT_FAIL_OPTION;
	}

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

    prog = bpf_object__find_program_by_name(obj, "xdp_prog");
    if (!prog) {
        printf("finding a prog in obj file failed\n");
        return -1;
    }

    /* load BPF program */
    if (bpf_object__load(obj)) {
        fprintf(stderr, "ERROR: loading BPF object file failed\n");
        return -1;
    }

    progFd = bpf_program__fd(prog);

    progs_fd = bpf_object__find_map_fd_by_name(obj, "jmp_table1");
    if (progs_fd < 0) {
        fprintf(stderr, "ERROR: finding a map in obj file failed\n");
        return -1;
    }

    bpf_object__for_each_program(prog, obj) {
        section = bpf_program__section_name(prog);
        /* register only syscalls to PROG_ARRAY */
        if (sscanf(section, "xdp_%d", &key) != 1)
            continue;

        fd = bpf_program__fd(prog);
        bpf_map_update_elem(progs_fd, &key, &fd, BPF_ANY);
    }

    /* Attach BPF program to interface */
    err = bpf_set_link_xdp_fd(ifindex, progFd, XDP_FLAGS_UPDATE_IF_NOEXIST);
    if (err) {
        fprintf(stderr, "ERR: ifindex(%d) link set xdp fd failed (%d): %s\n",
            ifindex, err, strerror(-err));
        return err;
    }
    printf("BPF attatched to interface: %d\n", ifindex);

    /* Keep going */
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);
    printf("Ctrl+c to exit and unload BPF\n");
    while(keep_running) {
//        assert(bpf_map_lookup_elem(mod_total_map_fd, &index, &value) == 0);
//        printf("Modified %lu packet(s).\n", value);
        printf(".\n");
        sleep(1);
    }
    printf("Stopped, start to unload BPF\n");

    /* Detach XDP from interface */
    if ((err = bpf_set_link_xdp_fd(ifindex, -1, XDP_FLAGS_UPDATE_IF_NOEXIST)) < 0) {
        fprintf(stderr, "ERR: link set xdp unload failed (err=%d):%s\n",
            err, strerror(-err));
        return err;
    }

    printf("Done\n");
    return 0;
}
