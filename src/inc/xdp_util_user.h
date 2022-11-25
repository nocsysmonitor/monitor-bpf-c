#ifndef _XDP_UTIL_USER_H_
#define _XDP_UTIL_USER_H_

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#define PIN_PATH_MAX    256
#define PIN_BASE_PATH   "/sys/fs/bpf"


/* MACRO DECLARATIONS
 */
#define xstr(s) str(s)
#define str(s)  #s


/* FUNCTION DECLARATIONS
 */
char *get_kern_prog_path(char *buffer_p, int buf_size, char *filename_p);

char *get_pin_path(char *sub_dir);

char *get_map_path(char *sub_dir, char *map_name);

/* Pinning maps under /sys/fs/bpf in subdir */
int pin_maps_in_bpf_object(
    struct bpf_object *bpf_obj, char *subdir, char *map_name_p, int is_pin);

int access_bpf_kern_map(
    struct bpf_object *obj_p, char *map_name_p);

int access_pinned_map (
    char *sub_dir_p, char *map_name_p,
    struct bpf_map_info *exp_info_p);

int check_map_fd_info(
    const struct bpf_map_info *info,
    const struct bpf_map_info *exp);

int open_bpf_map_file(
    char *file_path_p,
    struct bpf_map_info *info);

#endif

