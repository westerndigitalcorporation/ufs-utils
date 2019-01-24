/* SPDX-License-Identifier: GPL-2.0-only
 * Copyright (C) 2018 Western Digital Corporation
 */

#ifndef OPTIONS_H_
#define OPTIONS_H_
#include <stdint.h>

#define MAX_DEVICE_PATH_LEN 256

struct tool_options {
	/* desc/attr/fl/ */
	int config_type_inx;
	/* opt: -t, type - idn of decs/attribute/flag*/
	int idn;
	/* opt: -r/w/o/c/a, type of the operation read/write/toggle/clear */
	int opr;
	/* -i , currently using only for String Descriptor */
	int index;
	/* data for writing */
	void *data;
	int size;
	char path[MAX_DEVICE_PATH_LEN];
	char in_out_file[MAX_DEVICE_PATH_LEN];
	char keypath[MAX_DEVICE_PATH_LEN];
};


int init_options(int opt_cnt, char **opt_arr,
	struct tool_options *options);
#endif /* OPTIONS_H_ */
