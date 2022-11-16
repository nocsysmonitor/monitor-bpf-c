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
./build_deb.sh
```

## 3. install the deb generated in the above step.
```
dpkg -i xxx.deb
```
---

| Command     | Brief Description | Ex:
|:---         |:---         |:---
| xdp_cut_pkt | Truncate packets | xdp_cut_pkt -s 192.168.1.1 -i eth0 |

<!--- | xdp_deDup.py | Discard duplicate Packets | xdp_deDup.py eth0 |
| xdp_remTnlhdr.py | Remove GTPv1-U/Vxlan/GRE header | xdp_remTnlhdr.py eth0 | --->
