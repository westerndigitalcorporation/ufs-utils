/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Copyright (C) 2019 Western Digital Corporation or its affiliates */

#ifndef OPTIONS_H_
#define OPTIONS_H_
#include <stdint.h>
#include "ufs.h"

#define OK 0
#define ERROR -1
#define INVALID -1
#define WARNING -2

#ifndef _UAPI_LINUX_LIMITS_H
#define PATH_MAX 4096
#endif

#define READ 0
#define WRITE 1
#define CLEAR_FLAG 2
#define SET_FLAG 3
#define TOGGLE_FLAG 4
#define READ_ALL 5

#define ALIGNMENT_CHUNK_SIZE 4096

struct tool_options {
	/* one of @ufs_cong_type */
	enum ufs_cong_type config_type_inx;
	/* opt: -t, type - one of @flag_idn / @attr_idn / @desc_idn
	 * or @unipro attribute idn
	 */
	int idn;
	/* opt: -r/w/o/c/a, type of the operation read/write/toggle/clear */
	int opr;
	int index;
	int selector;
	/* data for writing */
	void *data;
	/* @DME_LOCAL or @DME_PEER */
	int target;
	int size;
	int offset;
	int len;
	/* HMR related */
	int hmr_method;
	int hmr_unit;
	/*start block address for rpmb cmd */
	int start_block;
	int num_block;
	int8_t lun;
	/*RPMB region*/
	int8_t region;
	int sg_type;
	char keypath[PATH_MAX];
	char path[PATH_MAX];
};

enum print_type {
	VERBOSE =	0,
	JSON,
	RAW_VALUE
};

extern char gl_pr_type;

int init_options(int opt_cnt, char **opt_arr, struct tool_options *options);
#endif /* OPTIONS_H_ */
