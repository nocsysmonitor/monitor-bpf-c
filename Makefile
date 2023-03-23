#
# Makefile for building eBPF programs
#

TARGETS := xdp_cut_pkt xdp_dedup xdp_rem_tnlhdr


LIBBPF_SRC= /home/vagrant/xdp-tools/lib/libbpf/src
LIBXDP_SRC= /home/vagrant/xdp-tools/lib/libxdp
OUTPUT_DIR= ${PWD}/build
SRC_DIR   = ${PWD}/src
DEP_DIR   = ${PWD}/.dep
#KERNELDIR = /usr/src/linux-headers-$(shell uname -r)/include

# Files under src/ have a name-scheme:
# ---------------------------------------------------
# The eBPF program is called xxx_kern.c. This is the restricted-C
# code, that need to be compiled with LLVM/clang, to generate an ELF
# binary containing the eBPF instructions.
#
# The userspace program called xxx_user.c, is a regular C-code
# program.


# Generate file name-scheme based on TARGETS
KERN_SOURCES = ${TARGETS:=_kern.c}
USER_SOURCES = ${TARGETS:=_user.c}
KERN_OBJECTS = ${KERN_SOURCES:.c=.o}
USER_OBJECTS = ${USER_SOURCES:.c=.o}

TARGETS_KERN = $(patsubst %.c, $(OUTPUT_DIR)/%.o, $(KERN_SOURCES))
TARGETS_USER = $(patsubst %, $(OUTPUT_DIR)/%, $(TARGETS))


# FLAGS for CLANG
CLFLAGS := -g -O2 -Wall
CLFLAGS += -I${SRC_DIR}/inc
CLFLAGS += -I${LIBBPF_SRC}/build/usr/include/
CLFLAGS += -I${LIBBPF_SRC}
CLFLAGS += -I${LIBXDP_SRC}/build/usr/local/include/
CLFLAGS += -I${LIBXDP_SRC}
CLFLAGS += -I/usr/include/

# Use ITMP=1 to generate intermediate files
CL_DBG_FLAGS := $(if $(ITMP), -v --save-temps, )

LDFLAGS = -lelf

EXTRA_CFLAGS=-Werror

DEPFLAGS = -MT $@ -MMD -MP -MF $(DEP_DIR)/$(patsubst %.c,%.d,$(<F))

# Local copy of header files taken from linux kernel
LINUXINCLUDE := -I${SRC_DIR}/inc/kernel

# Objects that xxx_user program is linked with:
USER_SOURCES_UTIL = xdp_util_user.c
USER_OBJECTS_UTIL = $(patsubst %.c, $(OUTPUT_DIR)/lib/%.o, $(USER_SOURCES_UTIL))

#
# The static libbpf library
LIBBPF = ${LIBBPF_SRC}/libbpf.a
LIBXDP = ${LIBXDP_SRC}/libxdp.a


# Allows pointing LLC/CLANG to another LLVM backend, redefine on cmdline:
#  make LLC=~/git/llvm/build/bin/llc CLANG=~/git/llvm/build/bin/clang
LLC ?= llc
CLANG ?= clang
CC = gcc

#NOSTDINC_FLAGS := -nostdinc -isystem $(shell $(CC) -print-file-name=include)

all: $(TARGETS_USER) $(TARGETS_KERN)

.PHONY: clean clean-tmp clean-deb clean-dep

clean: clean-tmp clean-deb clean-dep
	@find ${OUTPUT_DIR} ! -name '.gitignore' -type f -exec rm {} \;

clean-tmp:
	@find . -type f \( -name \*.bc -o -name \*.i -o -name \*.s \) -delete

clean-dep:
	@find ${DEP_DIR} ! -name '.gitignore' -type f -exec rm {} \;

# search .c under $(SRC_DIR), etc...
vpath %.c $(SRC_DIR)
vpath %.h $(SRC_DIR)/inc

# generate header dependency
DEPS = $(wildcard $(DEP_DIR)/*.d)
include $(DEPS)

$(DEP_DIR)/%.d: ;

# Compiling of eBPF restricted-C code with LLVM
#
${OUTPUT_DIR}/%_kern.o: %_kern.c $(DEP_DIR)/%_kern.d
	$(CLANG) $(DEPFLAGS) $(CL_DBG_FLAGS) $(CLFLAGS) $(LINUXINCLUDE) -target bpf -c $< -o $@

# util functions for xxx_user program
${OUTPUT_DIR}/lib/%.o: %.c $(DEP_DIR)/%.d
	$(CLANG) $(DEPFLAGS) $(CLFLAGS) -c $< -o $@

# generate user targets
${OUTPUT_DIR}/%: %_user.c $(USER_OBJECTS_UTIL) $(DEP_DIR)/%.d
	$(CLANG) $(DEPFLAGS) $(CLFLAGS) $(LDFLAGS) $< \
	    -o $@ $(USER_OBJECTS_UTIL) $(LIBXDP) $(LIBBPF) -lz

.DEFAULT_GOAL := all

# not to remove util.o, .d
.PRECIOUS: ${OUTPUT_DIR}/lib/%.o $(DEP_DIR)/%.d


#
# for building a simple debian package
#

GIT_COMMIT=$(shell git describe --dirty --always)

define DEB_control
Package: monitor-bpf
Version: 1.0~$(GIT_COMMIT)
Architecture: amd64
Description: Monitor BPF tools (C/#$(GIT_COMMIT))
Maintainer:

endef

DEB_PATH=$(PWD)/debian
DEB_NAME=monitor-bpf-1.0~$(GIT_COMMIT).deb

export DEB_control

print-control:
	@mkdir -p $(DEB_PATH)/DEBIAN
	@echo "$$DEB_control" > $(DEB_PATH)/DEBIAN/control

cp-bin:
	@mkdir -p $(DEB_PATH)/usr/local/bin
	@cp $(OUTPUT_DIR)/* $(DEB_PATH)/usr/local/bin/ | true

build-deb: all print-control cp-bin
	dpkg -b $(DEB_PATH) $(DEB_NAME)
	dpkg -c $(DEB_NAME)
	@cat $(DEB_PATH)/DEBIAN/control

clean-deb:
	@rm $(DEB_NAME) 2> /dev/null || true
	@rm -rf $(DEB_PATH) 2> /dev/null || true

