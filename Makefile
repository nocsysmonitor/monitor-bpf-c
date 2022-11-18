#
# Makefile for building eBPF programs
#

TARGETS := xdp_cut_pkt xdp_dedup
TARGETS += xdp_tail


LIBBPF_SRC= /home/vagrant/libbpf-0.4.0/src
OUTPUT_DIR= ${PWD}/build
SRC_DIR   = ${PWD}/src
#KERNELDIR = /usr/src/linux-headers-$(shell uname -r)/include

# Files under src/ have a name-scheme:
# ---------------------------------------------------
# The eBPF program is called xxx_kern.c. This is the restricted-C
# code, that need to be compiled with LLVM/clang, to generate an ELF
# binary containing the eBPF instructions.
#
# The userspace program called xxx_user.c, is a regular C-code
# program.


TARGETS_ALL = $(TARGETS)

# Generate file name-scheme based on TARGETS
KERN_SOURCES = ${TARGETS_ALL:=_kern.c}
USER_SOURCES = ${TARGETS_ALL:=_user.c}
KERN_OBJECTS = ${KERN_SOURCES:.c=.o}
USER_OBJECTS = ${USER_SOURCES:.c=.o}

# FLAGS for CLANG
CLFLAGS := -g -O2 -Wall
CLFLAGS += -I${SRC_DIR}/inc
CLFLAGS += -I${LIBBPF_SRC}/build/usr/include/
CLFLAGS += -I${LIBBPF_SRC}

LDFLAGS = -lelf

EXTRA_CFLAGS=-Werror

# Objects that xxx_user program is linked with:
OBJECTS_UTIL = xdp_util.o
OBJECTS_USER = $(patsubst %.o, $(OUTPUT_DIR)/lib/%.o, $(OBJECTS_UTIL))

#
# The static libbpf library
LIBBPF = ${LIBBPF_SRC}/libbpf.a


# Allows pointing LLC/CLANG to another LLVM backend, redefine on cmdline:
#  make LLC=~/git/llvm/build/bin/llc CLANG=~/git/llvm/build/bin/clang
LLC ?= llc
CLANG ?= clang
CC = gcc

#NOSTDINC_FLAGS := -nostdinc -isystem $(shell $(CC) -print-file-name=include)

all: $(TARGETS_ALL) $(KERN_OBJECTS)

.PHONY: clean 

clean:
	find ${OUTPUT_DIR} ! -name '.gitignore' -type f -exec rm {} \;
#	rm -f ${OUTPUT_DIR}/*

# Compiling of eBPF restricted-C code with LLVM
#
$(KERN_OBJECTS): %.o:
	$(CLANG) $(CLFLAGS) -target bpf -c $(SRC_DIR)/${@:.o=.c} -o ${OUTPUT_DIR}/$@

# util functions for xxx_user program
$(OBJECTS_UTIL): %.o:
	$(CLANG) $(CLFLAGS) -c $(SRC_DIR)/${@:.o=.c} -o ${OUTPUT_DIR}/lib/$@

$(TARGETS): %: $(OBJECTS_UTIL)
	$(CLANG) $(CLFLAGS) $(LDFLAGS) $(SRC_DIR)/$@_user.c \
	    -o ${OUTPUT_DIR}/$@ $(OBJECTS_USER) $(LIBBPF) -lz

.DEFAULT_GOAL := all

