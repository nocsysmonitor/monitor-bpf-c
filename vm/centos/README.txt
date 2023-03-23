OS Version:
CentOS Linux release 8.5.2111

Kernel Version:
Linux 5.11.0-1.el8.btf.x86_64

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

CentOS 8 needs a kernel (>=5.11.0) with BTF option enabled in kernel config,
currently, no available kernel can be download from  official repository.
Re-built rpms are provided, or you may have to rebuild kernel by the 'kernel-config.config'.

Necessary files for rebuilding the kernel can be found at below links.
kernel rpms:
https://linux.cc.iitk.ac.in/mirror/centos/elrepo/kernel/el8/x86_64/RPMS/
https://elrepo.org/linux/kernel/el8/x86_64/RPMS/
https://mirrors.coreix.net/elrepo-archive-archive/kernel/el8/x86_64/RPMS/

src.rpms:
https://linux.cc.iitk.ac.in/mirror/centos/elrepo/kernel/el8/SRPMS/

kernel.tar.xz:
https://cdn.kernel.org/pub/linux/kernel/v5.x/

