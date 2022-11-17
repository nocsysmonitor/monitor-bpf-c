LIBBPF_SRC=/home/vagrant/libbpf-0.4.0/src
OUTPUT_DIR=${PWD}/build
SRC_DIR=${PWD}/src

.PHONY: clean 

clean:
	rm -f ${OUTPUT_DIR}/*

xdp_cut_pkt_kern: ${SRC_DIR}/xdp_cut_pkt_kern.c
	clang -g -O2 -target bpf -c ${SRC_DIR}/xdp_cut_pkt_kern.c \
		-I${SRC_DIR}/inc \
		-I${LIBBPF_SRC}/build/usr/include/ \
		-o ${OUTPUT_DIR}/xdp_cut_pkt_kern.o

xdp_cut_pkt_user: ${SRC_DIR}/xdp_cut_pkt_user.c
	clang -o ${OUTPUT_DIR}/xdp_cut_pkt -g \
		-I${LIBBPF_SRC}/build/usr/include/ \
		-I${SRC_DIR}/inc \
		-I${LIBBPF_SRC} \
		${SRC_DIR}/xdp_cut_pkt_user.c -lz ${LIBBPF_SRC}/libbpf.a -lelf

xdp_tail_kern: ${SRC_DIR}/xdp_tail_kern.c
	clang -g -O2 -target bpf -c ${SRC_DIR}/xdp_tail_kern.c \
		-I${SRC_DIR}/inc \
		-I${LIBBPF_SRC}/build/usr/include/ \
		-I${LIBBPF_SRC} \
		-o ${OUTPUT_DIR}/xdp_tail_kern.o

xdp_tail_user:
	clang -o ${OUTPUT_DIR}/xdp_tail -g \
	    -I${LIBBPF_SRC}/build/usr/include/ \
	    -I${SRC_DIR}/inc \
	    -I${LIBBPF_SRC} \
	    ${SRC_DIR}/xdp_tail_user.c -lz ${LIBBPF_SRC}/libbpf.a -lelf

build: xdp_cut_pkt_kern xdp_cut_pkt_user xdp_tail_kern xdp_tail_user

.DEFAULT_GOAL := build

