/* SPDX-License-Identifier: GPL-2.0-only
 * Copyright (C) 2018 Western Digital Corporation
 */

#ifndef UFS_CMNDS_H_
#define UFS_CMNDS_H_

#include "options.h"

int do_desc(struct tool_options *opt);
int do_attributes(struct tool_options *opt);
int do_flags(struct tool_options *opt);
void print_command_help (char *prgname, int config_type);

#endif /* UFS_CMNDS_H_ */
