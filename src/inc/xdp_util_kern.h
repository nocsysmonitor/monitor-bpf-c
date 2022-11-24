#ifndef _XDP_UTIL_KERN_H_
#define _XDP_UTIL_KERN_H_

/* MACRO DECLARATIONS
 */
#define xstr(s) str(s)
#define str(s)  #s

#define bpf_debug(fmt, ...)                             \
        ({                                              \
            char ____fmt[] = fmt;                       \
            bpf_trace_printk(____fmt, sizeof(____fmt),  \
                     ##__VA_ARGS__);                    \
        })


// section name of xdp program must start with xdp
#define PROG(F) SEC("xdp" xstr(F)) int F

#define MAPS(F) struct bpf_map_def SEC("maps") F

#endif

