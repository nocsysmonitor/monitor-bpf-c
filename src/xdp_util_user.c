#include <stdio.h>
#include <libgen.h>
#include <unistd.h>
#include <errno.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "xdp_util_user.h"

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

char *get_pin_dir(char *sub_dir) {
    static char pin_dir[PIN_PATH_MAX] = {0};
    int len;

    if (pin_dir[0] == '\0') {
        len = snprintf(pin_dir, sizeof(pin_dir), "%s/%s", PIN_BASE_PATH, sub_dir);
        if (len < 0) {
            fprintf(stderr, "ERR: creating pin dir\n");
            return NULL;
        }
    }

    return pin_dir;
}

char *get_pin_map_path(char *sub_dir, char *map_name) {

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
// remove old pinned map if map_name exists
int pin_maps_in_bpf_object(
    struct bpf_object *bpf_obj, char *subdir, char *map_name_p, int is_pin) {

    char *map_path_p = NULL;
    char *pin_dir_p;
    int err;

    pin_dir_p = get_pin_dir(subdir);
    if (NULL == pin_dir_p)
        return -1;

    if (NULL != map_name_p) {
        map_path_p = get_pin_map_path(subdir, map_name_p);
        if (NULL == map_path_p)
            return -1;
    }

    /* Existing/previous XDP prog might not have cleaned up */
    if ((NULL == map_path_p) || (access(map_path_p, F_OK) != -1)) {
        printf(" - Unpinning (remove) prev maps in %s/\n", pin_dir_p);

        /* Basically calls unlink(3) on map_filename */
        err = bpf_object__unpin_maps(bpf_obj, pin_dir_p);
        if (err) {
        //    fprintf(stderr, "ERR: UNpinning maps in %s\n", pin_dir_p);
        //    return -1;
        }
    }

    if (is_pin != 0) {
        printf(" - Pinning maps in %s/\n", pin_dir_p);

        /* This will pin all maps in our bpf_object */
        err = bpf_object__pin_maps(bpf_obj, pin_dir_p);
        if (err) {
            fprintf(stderr, "try to mount bpf fs first ! (mount -t bpf /sys/fs/bpf/)\n");
            return -1;
        }
    }

    return 0;
}

int access_bpf_kern_map(
    struct bpf_object *obj_p, char *map_name_p) {

    int map_fd;

    map_fd = bpf_object__find_map_fd_by_name(obj_p, map_name_p);
    if (map_fd < 0) {
        fprintf(stderr, "ERR: finding %s in obj file failed\n", map_name_p);
    }

    return map_fd;
}

int access_pinned_map(
    char *sub_dir_p, char *map_name_p,
    struct bpf_map_info *exp_info_p) {

    char *map_path_p;
    int map_fd, err;
    struct bpf_map_info info = { 0 };

    map_path_p = get_pin_map_path(sub_dir_p, map_name_p);
    if (NULL == map_path_p)
        return -1;

    map_fd = open_bpf_map_file(map_path_p, &info);
    if (map_fd < 0) {
        fprintf(stderr, "ERR: access pinned map (%s) failed\n", map_name_p);
        return -1;
    }

    /* check map info, e.g. datarec is expected size */
    if (NULL != exp_info_p) {
        err = check_map_fd_info(&info, exp_info_p);
        if (err) {
            fprintf(stderr, "ERR: map via FD not compatible\n");
            return -1;
        }
    }

    return map_fd;
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

/* For suppressing useless warning message from libbpf */
int libbpf_silent_func(
    enum libbpf_print_level level,
    const char *format,
    va_list args)
{
    (void)level;
    (void)format;
    (void)args;
    return 0;
}

void silence_libbpf_logging()
{
    libbpf_set_print(libbpf_silent_func);
}

