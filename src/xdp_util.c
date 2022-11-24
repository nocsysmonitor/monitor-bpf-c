#include <stdio.h>
#include <libgen.h>
#include <unistd.h>

#include <errno.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "xdp_util.h"

//dirname/basename may modify the contents of input path
//filename_p: pointer to input filename without path, ex: xxx
char *get_kern_prog_path(char *buffer_p, int buf_size, char *filename_p) {
    char buf[1024] = {0};

    /* Note we use sizeof(buf)-1 since we may need an extra char for NUL. */
    if (readlink("/proc/self/exe", buf, sizeof(buf)-1) < 0) {
        /* There was an error...  Perhaps the path does not exist
         * or the buffer is not big enough.  errno has the details. */
        perror("readlink");
        return NULL;
    }

    snprintf(buffer_p, buf_size, "%s/%s", dirname(buf), filename_p);
    return buffer_p;
}

int check_map_fd_info(
    const struct bpf_map_info *info,
    const struct bpf_map_info *exp) {

    if (exp->key_size && exp->key_size != info->key_size) {
        fprintf(stderr, "ERR: %s() "
            "Map key size(%d) mismatch expected size(%d)\n",
            __func__, info->key_size, exp->key_size);
        return -1;
    }
    if (exp->value_size && exp->value_size != info->value_size) {
        fprintf(stderr, "ERR: %s() "
            "Map value size(%d) mismatch expected size(%d)\n",
            __func__, info->value_size, exp->value_size);
        return -1;
    }
    if (exp->max_entries && exp->max_entries != info->max_entries) {
        fprintf(stderr, "ERR: %s() "
            "Map max_entries(%d) mismatch expected size(%d)\n",
            __func__, info->max_entries, exp->max_entries);
        return -1;
    }
    if (exp->type && exp->type  != info->type) {
        fprintf(stderr, "ERR: %s() "
            "Map type(%d) mismatch expected type(%d)\n",
            __func__, info->type, exp->type);
        return -1;
    }

    return 0;
}

int open_bpf_map_file(
    char *file_path_p,
    struct bpf_map_info *info) {

    int err, fd;
    __u32 info_len = sizeof(*info);

    /* Lesson#1: There is only a weak dependency to libbpf here as
     * bpf_obj_get is a simple wrapper around the bpf-syscall
     */
    fd = bpf_obj_get(file_path_p);
    if (fd < 0) {
        fprintf(stderr,
            "ERR: Failed to open bpf map file - %s: (%d, %s)\n",
            file_path_p, errno, strerror(errno));
        return fd;
    }

    if (info) {
        err = bpf_obj_get_info_by_fd(fd, info, &info_len);
        if (err) {
            fprintf(stderr, "ERR: can't get map info - %s: (%d, %s)\n",
                file_path_p, errno, strerror(errno));
            return -1;
        }
    }

    return fd;
}

