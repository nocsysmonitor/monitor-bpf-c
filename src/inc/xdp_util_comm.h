#ifndef _XDP_UTIL_COMM_H_
#define _XDP_UTIL_COMM_H_

// common description for user program
#define prog_doc        "\n dev is required for loading kernel program.\n"\
                        "\v NOTE: need to mount the bpf fs first, i.e.,"\
                        " mount -t bpf bpf /sys/fs/bpf/\n"

// common arg descrption for user program
#define args_doc        "[dev]"

// common option description for user proram
#define inf_help        "The name of interface to use."
#define lst_help        "Show kernel program's information."
#define det_help        "Detach kernel program already attached first"\
                        " (effect only when dev is specified)."


/* MACRO DECLARATIONS
 */

#endif

