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
| xdp_cut_pkt | Truncate packets <br> (apply only for ipv6/ipv4 udp/tcp packets, sip filtering is available for ipv4)  | xdp_cut_pkt -e 1.1.1.1 -e 2.2.2.2 eth0 |
| xdp_dedup | Discard duplicate packets | xdp_dedup eth0 |
| xdp_rem_tnlhdr| Remove GTPv1-U/Vxlan/GRE/GENEVE header | xdp_rem_tnlhdr eth0 |

NOTE:
1. Use {command} --help for more information.

2. Need to mount bpf fs first, i.e., mount -t bpf /sys/fs/bpf/.

3. To unload BPF kernel program correclty, use "kill -TERM {pid}" to stop the process.

4. Use "bpftool net detach xdp dev {dev}" to unload BPF kernel program manually.

5. Use "{command} -u {dev}" to detach kernel program if previous kernel program is not detached correctly.

