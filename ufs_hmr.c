// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2019 Western Digital Corporation or its affiliates */

#include <stdio.h>
#include <stdint.h>
#include <errno.h>
#include <sys/types.h>

#include "ufs.h"
#include "ufs_hmr.h"

int do_hmr(struct tool_options *opt)
{
	print_error("not yet supported");
	return -ENOTSUP;
}

void hmr_help(char *tool_name)
{
	/* General use case description */
	printf("\n HMR command usage:\n");
	printf("\n\t%s hmr [-p] <path to device> ([-x] <method> [-y] <unit>)\n",
		tool_name);

	/* -p: mandatory, device path */
	printf("\n\t-p\t path - mandatory, ufs-bsg device path\n");

	/* -x: optional, HMR method */
	printf("\n\t-x\t method - optional, the default is %d\n",
		HMR_METHOD_SELECTIVE);
	printf("\t\t\t %-3d: %-25s\n",
		HMR_METHOD_FORCE, "force, refresh all blocks containing data");
	printf("\t\t\t %-3d: %-25s\n",
		HMR_METHOD_SELECTIVE, "selective, refresh marked blocks only");

	/* -y: optional, HMR unit */
	printf("\n\t-y\t unit - optional, the default is %d\n", HMR_UNIT_MIN);
	printf("\t\t\t %-3d: %-25s\n",
		HMR_UNIT_MIN, "minimum, perform HMR by minimum refresh units");
	printf("\t\t\t %-3d: %-25s\n",
		HMR_UNIT_FULL, "full, perform a full HMR cycle in one command");
}

