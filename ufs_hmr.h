/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Copyright (C) 2019 Western Digital Corporation or its affiliates */

#ifndef UFS_HMR_H_
#define UFS_HMR_H_

#include "options.h"

enum ufs_hmr_method {
	HMR_METHOD_FORCE = 1,	/* refresh all blocks containing data */
	HMR_METHOD_SELECTIVE,	/* refresh marked blocks only */
	HMR_METHOD_MAX			/* last member indicator */
};

enum ufs_hmr_unit {
	HMR_UNIT_MIN = 0,	/* perform HMR in small steps (minimum refresh units) */
	HMR_UNIT_FULL,		/* perform full HMR cycle in one command */
	HMR_UNIT_MAX		/* last member indicator */
};

void hmr_help(char *tool_name);
int do_hmr(struct tool_options *opt);
#endif /* UFS_HMR_H_ */

