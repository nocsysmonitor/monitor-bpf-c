LIBBPF_SRC=/home/vagrant/libbpf-0.4.0/src
OUTPUT_DIR=${PWD}/build
SRC_DIR=${PWD}/src

.PHONY: clean 

clean:
	rm -f ${OUTPUT_DIR}/*

bpf: ${SRC_DIR}/xdp_cut_pkt_kern.c
	clang -g -O2 -target bpf -c ${SRC_DIR}/xdp_cut_pkt_kern.c \
		-I${SRC_DIR}/inc \
		-I${LIBBPF_SRC}/build/usr/include/ \
		-o ${OUTPUT_DIR}/xdp_cut_pkt_kern.o

loader: ${SRC_DIR}/xdp_cut_pkt_user.c
	clang -o ${OUTPUT_DIR}/xdp_cut_pkt -g \
		-I${LIBBPF_SRC}/build/usr/include/ \
		-I${SRC_DIR}/inc \
		-L${LIBBPF_SRC} \
		${SRC_DIR}/xdp_cut_pkt_user.c -lz ${LIBBPF_SRC}/libbpf.a -lelf

build: bpf loader

.DEFAULT_GOAL := build

