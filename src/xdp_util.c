#include <stdio.h>
#include <libgen.h>
#include <unistd.h>

char *get_prog_path(char *buffer_p, int buf_size, char *filename_p) {
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

