/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Copyright (C) 2019 Western Digital Corporation or its affiliates */

#ifndef OPTIONS_H_
#define OPTIONS_H_
#include <stdint.h>

#define OK 0
#define ERROR -1
#define INVALID -1

#ifndef _UAPI_LINUX_LIMITS_H
#define PATH_MAX 4096
#endif

#define READ 0
#define WRITE 1
#define CLEAR_FLAG 2
#define SET_FLAG 3
#define TOGGLE_FLAG 4
#define READ_ALL 5

struct tool_options {
	/* one of @ufs_cong_type */
	int config_type_inx;
	/* opt: -t, type - one of @flag_idn / @attr_idn / @desc_idn */
	int idn;
	/* opt: -r/w/o/c/a, type of the operation read/write/toggle/clear */
	int opr;
	int index;
	int selector;
	/* data for writing */
	void *data;
	int size;
	char path[PATH_MAX];
};

int init_options(int opt_cnt, char **opt_arr, struct tool_options *options);
#endif /* OPTIONS_H_ */
