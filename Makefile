# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2019 Western Digital Corporation or its affiliates

UNAME := $(shell uname -s)

ifeq ($(UNAME),FreeBSD)
export CC := cc
else
export CC := $(CROSS_COMPILE)gcc
endif
AM_CFLAGS = -D_FILE_OFFSET_BITS=64 -D_FORTIFY_SOURCE=2
CFLAGS ?= -g -O2 -static -D_GNU_SOURCE

ifneq ($(CROSS_COMPILE),)
	LDFLAGS += -static
endif

#CXXFLAGS = -DDEBUG

objects = \
	ufs.o \
	ufs_cmds.o \
	options.o \
	scsi_bsg_util.o \
	ufs_err_hist.o \
	unipro.o \
	ufs_ffu.o \
	ufs_vendor.o\
	hmac_sha2.o \
	sha2.o \
	ufs_rpmb.o \
	ufs_arpmb.o \
	ufs_hmr.o \
	ufs_emon.o \

ifeq ($(UNAME),FreeBSD)
objects += freebsd_transport.o
# compat carries the Linux headers ufs-utils includes.
INC_DIR += -I$(CURDIR)/compat
# options.h defines PATH_MAX itself unless a Linux guard macro says the
# system already has one. Pull in the real limits.h and set that guard,
# so the platform value is used instead of a second definition.
AM_CFLAGS += -include limits.h -D_UAPI_LINUX_LIMITS_H
endif

CHECKFLAGS = -Wall  -Wundef -Wno-missing-braces -fcommon

DEPFLAGS = -Wp,-MMD,$(@D)/.$(@F).d,-MT,$@
override CFLAGS := $(CHECKFLAGS) $(AM_CFLAGS) $(CFLAGS) $(INC_DIR) $(CXXFLAGS)
progs = ufs-utils
ifdef C
	check = sparse $(CHECKFLAGS)
endif

.c.o:
ifdef C
	$(check) $<
endif
	$(CC) $(CPPFLAGS) $(CFLAGS) $(DEPFLAGS) -c $< -o $@

ufs-utils:$(objects)
	$(CC) $(CFLAGS) -o $@ $(objects) $(LDFLAGS) $(LIBS)

help:
	@echo "\033[31m==============Build Instructions==============\033[0m"
	@echo "\033[92mTo build ufs_utils follow the following steps\033[0m"
	@echo "\033[92m1 Set CROSS_COMPILE variable\033[0m"
	@echo "\033[92m2 Build the tool using \"make\"\033[0m"
	@echo "\033[92m3 Clean the tool using \"make clean\"\033[0m"

clean:
	@rm -f $(progs) $(objects) .*.o.d
.PHONY: all clean
