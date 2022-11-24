# Quick steps to build the deb

## 0. download the source code
```
git clone https://github.com/SquidRo/acc-bpf2
```

## 1. boot vm (vagrant is required)
```
cd vm/ubuntu
vagrant up vm1
```

## 2. download the source code inside the vm1
```
cd acc-bpf2
make build-deb
```

## 3. install the deb generated in the above step.
```
dpkg -i xxx.deb
```
---

| Command     | Brief Description | Ex:
|:---         |:---         |:---
| xdp_cut_pkt | Truncate packets | xdp_cut_pkt -e 192.168.1.1 -i eth0 |
| xdp_dedup | Discard duplicate packets | xdp_dedup -i eth0 |
| xdp_rem_tnlhdr| Remove GTPv1-U/Vxlan/GRE/GENEVE header | xdp_rem_tnlhdr -i eth0 |

NOTE:
1. Use {command} --help for more information.

2. Use kill -TERM {pid} to stop the process, then the BPF program can be unloaded correclty. Otherwise, it may need to use "bpftool net detach xdp dev {dev}" to unload BPF program manually.
