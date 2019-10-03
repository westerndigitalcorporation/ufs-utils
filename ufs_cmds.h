/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Copyright (C) 2019 Western Digital Corporation or its affiliates */

#ifndef UFS_CMNDS_H_
#define UFS_CMNDS_H_

#include "options.h"
#include <asm-generic/int-ll64.h>


enum field_width {
	BYTE	= (1 << 0),
	WORD	= (1 << 1),
	DWORD	= (1 << 2),
	DDWORD	= (1 << 3)
};

struct desc_field_offset {
	char *name;
	int offset;
	enum field_width width_in_bytes;
};

int do_desc(struct tool_options *opt);
int do_attributes(struct tool_options *opt);
int do_flags(struct tool_options *opt);
void print_command_help (char *prgname, int config_type);
int do_device_desc(int fd, __u8 *desc_buff);
void desc_help(char *tool_name);
void attribute_help(char *tool_name);
void flag_help(char *tool_name);
#endif /* UFS_CMNDS_H_ */
