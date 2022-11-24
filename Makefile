#
# Makefile for building eBPF programs
#

TARGETS := xdp_cut_pkt xdp_dedup xdp_rem_tnlhdr


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
CLFLAGS += -I/usr/include/

# Use ITMP=1 to generate intermediate files
CL_DBG_FLAGS := $(if $(ITMP), -v --save-temps, )

LDFLAGS = -lelf

EXTRA_CFLAGS=-Werror

# Local copy of header files took from linux kernel
LINUXINCLUDE := -I${SRC_DIR}/inc/kernel

# Objects that xxx_user program is linked with:
OBJECTS_UTIL = xdp_util_user.o
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

.PHONY: clean clean-tmp clean-deb

clean: clean-tmp clean-deb
	find ${OUTPUT_DIR} ! -name '.gitignore' -type f -exec rm {} \;

clean-tmp:
	find . -type f \( -name \*.bc -o -name \*.i -o -name \*.s \) -delete

# Compiling of eBPF restricted-C code with LLVM
#
$(KERN_OBJECTS): %.o:
	$(CLANG) $(CL_DBG_FLAGS) $(CLFLAGS) $(LINUXINCLUDE) -target bpf -c $(SRC_DIR)/${@:.o=.c} -o ${OUTPUT_DIR}/$@

# util functions for xxx_user program
$(OBJECTS_UTIL): %.o:
	$(CLANG) $(CLFLAGS) -c $(SRC_DIR)/${@:.o=.c} -o ${OUTPUT_DIR}/lib/$@

$(TARGETS): %: $(OBJECTS_UTIL)
	$(CLANG) $(CLFLAGS) $(LDFLAGS) $(SRC_DIR)/$@_user.c \
	    -o ${OUTPUT_DIR}/$@ $(OBJECTS_USER) $(LIBBPF) -lz

.DEFAULT_GOAL := all


#
# for building a simple debian package
#

GIT_COMMIT=$(shell git describe --dirty --always)

define DEB_control
Package: acc-bpf
Version: 1.0~$(GIT_COMMIT)
Architecture: amd64
Description: Accton BPF tools (C/#$(GIT_COMMIT))
Maintainer:

endef

DEB_PATH=$(PWD)/debian

export DEB_control

print-control:
	mkdir -p $(DEB_PATH)/DEBIAN
	@echo "$$DEB_control" > $(DEB_PATH)/DEBIAN/control

cp-bin:
	mkdir -p $(DEB_PATH)/usr/local/bin
	cp $(OUTPUT_DIR)/* $(DEB_PATH)/usr/local/bin/ | true

build-deb: all print-control cp-bin
	dpkg -b $(DEB_PATH) acc-bpf.deb
	dpkg -c acc-bpf.deb

clean-deb:
	rm acc-bpf.deb
	rm -rf $(DEB_PATH)
