CentOS version is not supported to load multiple BPF programs on one interface.
Use Ubuntu version instead.

OS Version:
CentOS Linux release 8.5.2111

Kernel Version:
Linux 5.11.0-1.el8.elrepo.x86_64

LIBBPF Version:
1.0.0

To run BPF in centos, codes below are necessary, even though not using any BPF maps:
"""""""""""""""""""""""""""""""""""""""""""""""""""""""""
#include <sys/resource.h>

int main() {
	...
	struct rlimit r = {RLIM_INFINITY, RLIM_INFINITY};

	if (setrlimit(RLIMIT_MEMLOCK, &r)) {
	        perror("setrlimit(RLIMIT_MEMLOCK)");
	        return -1;
	}
	...
}
"""""""""""""""""""""""""""""""""""""""""""""""""""""""""

If kernel files are removed or default version is changed, try following links:
https://linux.cc.iitk.ac.in/mirror/centos/elrepo/kernel/el8/x86_64/RPMS/
https://elrepo.org/linux/kernel/el8/x86_64/RPMS/
https://mirrors.coreix.net/elrepo-archive-archive/kernel/el8/x86_64/RPMS/
