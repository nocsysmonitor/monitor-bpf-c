LIBBPF_SRC=/home/vagrant/libbpf-0.4.0/src

.PHONY: clean 

clean:
	rm -f program.o
	rm -f loader

bpf: 	program.c 
	clang -g -O2 -target bpf -c program.c -I${LIBBPF_SRC}/build/usr/include/ -o program.o

loader:	loader.c
	clang -o loader -g \
		-I${LIBBPF_SRC}/build/usr/include/ \
		-L${LIBBPF_SRC} \
		loader.c -lz ${LIBBPF_SRC}/libbpf.a -lelf

build: bpf loader

.DEFAULT_GOAL := build
