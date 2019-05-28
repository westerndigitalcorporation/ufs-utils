// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2019 Western Digital Corporation or its affiliates */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdint.h>
#include <errno.h>

#include "ufs_cmds.h"
#include "options.h"
#include "ufs.h"

#define UFS_BSG_UTIL_VERSION	"1.0"
typedef int (*command_function)(struct tool_options *opt);

struct tool_command {
	command_function func; /* function which implements the command */
	char *conf_type; /* one of: descriptor/attributes/flags */
	int conf_type_ind; /* confiruration type index */
};

static struct tool_command commands[] = {
	/*
	 * avoid short commands different for the case only
	 */
	{ do_desc, "desc", DESC_TYPE},
	{ do_attributes, "attr", ATTR_TYPE},
	{ do_flags, "fl", FLAG_TYPE},
	{ 0, 0, 0}
};

static char *get_prgname(char *programname)
{
	char	*np;

	np = strrchr(programname, '/');
	if (!np)
		np = programname;
	else
		np++;

	return np;
}

static void help(char *np)
{
	char help_str[256] = {0};

	strcat(help_str, "<desc | attr | fl");
	strcat(help_str, ">");
	printf("\n Usage:\n");
	printf("\n\t%s help|--help|-h\n\t\tShow the help.\n", np);
	printf("\n\t%s -v\n\t\tShow the version.\n", np);
	printf("\n\t%s %s%s", np, help_str,
		" --help|-h\n\t\tShow detailed help for a command\n");
}

static void initialized_options(struct tool_options *options)
{
	memset(options, INVALID, sizeof(*options));
	options->path[0] = '\0';
	options->data = NULL;
}

static int parse_args(int argc, char **argv, command_function *func,
		struct tool_options *options)
{
	int rc = OK;
	struct tool_command *cp;
	char *prgname = get_prgname(argv[0]);

	if (argc == 2 && !strcmp(argv[1], "-v")) {
		printf("\n\t %s ver: %s\n", prgname, UFS_BSG_UTIL_VERSION);
		goto out;
	} else if (argc <= 2) {
		help(prgname);
		goto out;
	}

	for (cp = commands; cp->conf_type; cp++) {
		if (!strcmp(argv[1], cp->conf_type)) {
			options->config_type_inx = cp->conf_type_ind;
			*func = cp->func;
			break;
		}
	}

	if (options->config_type_inx == INVALID) {
		print_error("Please enter the correct config type");
		help(prgname);
		rc = -EINVAL;
		goto out;
	}

	if (argc == 3 &&
		(!strcmp(argv[2], "-h") || !strcmp(argv[2], "--help"))) {
		print_command_help(prgname, options->config_type_inx);
		*func = 0;
		goto out;
	}

	rc = init_options(argc, argv, options);

out:
	return rc;
}

void print_error(const char *msg, ...)
{
	va_list args;

	printf("\n Err: ");
	va_start(args, msg);
	vprintf(msg, args);
	va_end(args);
	printf("\n");
}

int main(int ac, char **av)
{
	int rc;
	command_function func = NULL;
	struct tool_options options;

	initialized_options(&options);

	rc = parse_args(ac, av, &func, &options);
	if (rc)
		goto out;

	if (func)
		rc = func(&options);

out:
	if (options.data)
		free(options.data);
	return rc ? EXIT_FAILURE : EXIT_SUCCESS;
}

