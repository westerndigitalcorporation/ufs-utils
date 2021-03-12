/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Copyright (C) 2019 Western Digital Corporation or its affiliates */

#ifndef UFS_CMNDS_H_
#define UFS_CMNDS_H_

#include "options.h"
#include <asm/types.h>


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

enum acc_mode {
	READ_NRML =	(1 << 0),
	READ_ONLY =	(1 << 1),
	WRITE_ONLY =	(1 << 2),
	WRITE_ONCE =	(1 << 3),
	WRITE_PRSIST =	(1 << 4),
	WRITE_VLT =	(1 << 5),
	SET_ONLY =	(1 << 6),
	WRITE_PWR =	(1 << 7),
	MODE_INVALID =	(1 << 8)
};

enum attr_level {
	DEV =		(1 << 0),
	ARRAY =		(1 << 1),
	LEVEL_INVALID =	(1 << 2)
};

enum access_type {
	URD =		(1 << 0),
	UWRT =		(1 << 1),
	ACC_INVALID =	(1 << 2)
};

struct attr_fields {
	char *name;
	enum field_width width_in_bytes;
	enum access_type acc_type;
	enum acc_mode acc_mode;
	enum attr_level device_level;
};

struct flag_fields {
	char *name;
	enum access_type acc_type;
	enum acc_mode acc_mode;
	enum attr_level device_level;
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
