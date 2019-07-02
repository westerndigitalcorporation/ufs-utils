// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2019 Western Digital Corporation or its affiliates */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <errno.h>

#include "options.h"
#include "ufs.h"
#include "unipro.h"

static int verify_and_set_idn(struct tool_options *options);
static int verify_read(struct tool_options *options);
static int verify_write(struct tool_options *options);
static int verify_and_set_flag_operation(int opr_type,
					 struct tool_options *options);
static int verify_and_set_device_path(struct tool_options *options);
static int verify_arg_and_set_default(struct tool_options *options);
static int verify_and_set_index(struct tool_options *options);
static int verify_and_set_selector(struct tool_options *options);
static int verify_target(struct tool_options *options, int target);

int init_options(int opt_cnt, char *opt_arr[], struct tool_options *options)
{
	int rc = -EINVAL;
	int curr_opt = 0;
	int opt = 0;

	static struct option long_opts[] = {
		{"peer", no_argument, NULL, 'u'}, /* UFS device */
		{"local", no_argument, NULL, 'l'}, /* UFS host*/
		{NULL, 0, NULL, 0}
	};
	static char *short_opts = "t:p:w:i:s:rocea";

	while (-1 !=
	      (curr_opt = getopt_long(opt_cnt, opt_arr, short_opts,
				      long_opts, &opt))) {
		switch (curr_opt) {
		case 'a':
			rc = verify_read(options);
			if (!rc)
				options->opr = READ_ALL;
			break;
		case 't':
			rc = verify_and_set_idn(options);
			break;
		case 'r':
			rc = verify_read(options);
			if (!rc)
				options->opr = READ;
			break;
		case 'w':
			rc = verify_write(options);
			if (!rc)
				options->opr = WRITE;
			break;
		case 'c':
			rc = verify_and_set_flag_operation(CLEAR_FLAG,
							options);
			break;
		case 'e':
			rc = verify_and_set_flag_operation(SET_FLAG, options);
			break;
		case 'o':
			rc = verify_and_set_flag_operation(TOGGLE_FLAG,
							options);
			break;
		case 'p':
			rc = verify_and_set_device_path(options);
			break;
		case 'i':
			rc = verify_and_set_index(options);
			break;
		case 's':
			rc = verify_and_set_selector(options);
			break;
		case 'u':
			rc = verify_target(options, DME_PEER);
			break;
		case 'l':
			rc = verify_target(options, DME_LOCAL);
			break;
		default:
			rc = -EINVAL;
			break;
		}
		if (rc)
			break;
	}

	if (!rc)
		rc = verify_arg_and_set_default(options);

	return rc;
}

static int verify_target(struct tool_options *options, int target)
{
	if (options->target != INVALID) {
		print_error("duplicated operate target.");
		goto out;
	}

	options->target = target;
	return OK;

out:
	return ERROR;
}

static int verify_and_set_index(struct tool_options *options)
{
	int index = INVALID;

	if (options->index != INVALID) {
		print_error("duplicated index");
		goto out;
	}

	/* In case atoi returned 0 . Check that is real 0 and not error
	 * arguments . Also check that the value is in correct range
	 */
	if (strstr(optarg, "0x") || strstr(optarg, "0X"))
		index = (int)strtol(optarg, NULL, 0);
	else
		index = atoi(optarg);

	if (!optarg || (index == 0 && strcmp(optarg, "0")) || index < 0) {
		print_error("Invalid argument for index");
		goto out;
	}

	options->index = index;
	return OK;

out:
	return ERROR;
}

static int verify_and_set_selector(struct tool_options *options)
{
	int selector = INVALID;

	if (options->selector != INVALID) {
		print_error("duplicated selector");
		goto out;
	}

	/* In case atoi returned 0 . Check that is real 0 and not error
	 * arguments . Also check that the value is in correct range
	 */
	selector = atoi(optarg);
	if (!optarg || (selector == 0 && strcmp(optarg, "0")) || selector < 0) {
		print_error("Invalid argument for selector");
		goto out;
	}

	options->selector = selector;
	return OK;

out:
	return ERROR;
}

static int verify_and_set_idn(struct tool_options *options)
{
	int idn = INVALID;

	if (options->idn != INVALID) {
		print_error("duplicated desc type option");
		goto out;
	}

	/* In case atoi returned 0. Check that is real 0 and not error
	 * arguments. Also check that the value is in correct range
	 */
	idn = atoi(optarg);
	if (!optarg || (idn == 0 && strcmp(optarg, "0")) || idn < 0) {
		print_error("Invalid argument for idn");
		goto out;
	}

	switch (options->config_type_inx) {
	case DESC_TYPE:
		if (idn > QUERY_DESC_IDN_MAX) {
			print_error("Invalid descriptor idn %d", idn);
			goto out;
		}
		break;
	case ATTR_TYPE:
		if (idn >= QUERY_ATTR_IDN_MAX) {
			print_error("Invalid attr idn %d", idn);
			goto out;
		}
		break;
	case FLAG_TYPE:
		if (idn > QUERY_FLAG_IDN_PERMANENTLYDISABLEFW) {
			print_error("Invalid flag idn %d", idn);
			goto out;
		}
		break;
	case UIC_TYPE:
		if (idn >= MAX_UNIPRO_IDN) {
			print_error("Invalid UIC idn %d", idn);
			goto out;
		}
		break;
	default:
		print_error("Invalid UFS configuration type %d", idn);
		goto out;
	}

	options->idn = idn;
	return OK;

out:
	return ERROR;
}

static int verify_arg_and_set_default(struct tool_options *options)
{
	if (options->path[0] == '\0') {
		print_error("Missing device path type");
		goto out;
	}

	if (options->opr == INVALID)
		options->opr = READ;

	if (options->opr == WRITE && !options->data) {
		print_error("Data missed for the write operation");
		goto out;
	}

	if (options->opr != READ_ALL && options->idn == INVALID) {
		print_error("The type idn is missed");
		goto out;
	}

	if (options->config_type_inx == DESC_TYPE &&
		options->idn == QUERY_DESC_IDN_STRING &&
		options->index == INVALID) {
		print_error("The index is missed");
		goto out;
	}

	if (options->config_type_inx == UIC_TYPE) {
		if (options->idn == INVALID) {
			/*
			 * As for the Unipro attributes access, should always
			 * specify idn.
			 */
			print_error("idn of Unipro attributes is missed");
			goto out;
		}

		if (options->opr == WRITE && options->target != DME_PEER &&
		    options->target != DME_LOCAL) {
			/*
			 * As for Unipro attributes write, should
			 * specify accessing target.
			 */
			print_error("accessing target is missed");
			goto out;
		}

		if (options->index == INVALID &&
		    (options->opr == READ || options->opr == WRITE)) {
			print_error("ID of Unipro attributes is missed");
			goto out;
		}
	}

	if (options->index == INVALID)
		options->index = 0;

	if (options->selector == INVALID)
		options->selector = 0;

	return OK;

out:
	return ERROR;
}

static int verify_and_set_device_path(struct tool_options *options)
{
	if (options->path[0] != '\0') {
		print_error("Duplicate Device path %d", options->path[0]);
		goto out;
	}

	if (!optarg || optarg[0] == 0) {
		print_error("Device path missed");
		goto out;
	}

	if (strlen(optarg) >= PATH_MAX) {
		print_error("Device path is too long");
		goto out;
	}

	strcpy(options->path, optarg);
	return OK;

out:
	return ERROR;
}

static int verify_read(struct tool_options *options)
{
	if (options->opr != INVALID) {
		print_error("duplicated operation option(read) 2%d",
			    options->opr);
		goto out;
	}

	return OK;

out:
	return ERROR;
}

static int verify_write(struct tool_options *options)
{
	char *endptr;

	errno = 0;

	if (options->opr != INVALID) {
		print_error("duplicated operation option(write)");
		goto out;
	}

	if (!optarg || optarg[0] == 0) {
		print_error("Data is missed");
		goto out;
	}

	if (options->config_type_inx == DESC_TYPE) {
		int arg_len = strlen(optarg);
		int str_desc_max_len = QUERY_DESC_STRING_MAX_SIZE/2 - 2;

		if (options->idn != QUERY_DESC_IDN_CONFIGURAION &&
			options->idn != QUERY_DESC_IDN_STRING) {
			print_error("write unavailable for descriptor = %d",
				options->idn);
			goto out;
		}

		if (arg_len > str_desc_max_len) {
			print_error("Input data is too big");
			goto out;
		}

		options->data = (char *)malloc(QUERY_DESC_STRING_MAX_SIZE);
		if (!options->data) {
			print_error("Memory Allocation problem");
			goto out;
		}

		strcpy(options->data, optarg);
	}

	if (options->config_type_inx == FLAG_TYPE) {
		print_error("Please use 'c', 'e', or 'o' for flag operations");
		goto out;
	}

	if (options->config_type_inx == ATTR_TYPE ||
	    options->config_type_inx == UIC_TYPE) {
		options->data = (__u32 *)calloc(1, sizeof(__u32));
		if (!options->data) {
			print_error("Memory Allocation problem");
			goto out;
		}

		*(__u32 *)options->data = strtol(optarg, &endptr, 16);

		if (errno != 0 || *endptr != '\0') {
			print_error("Wrong data");
			goto out;
		}
	}

	return OK;

out:
	return ERROR;
}

static int
verify_and_set_flag_operation(int opr_type, struct tool_options *options)
{
	if (options->opr != INVALID) {
		print_error("duplicated operation option");
		goto out;
	}

	if (options->config_type_inx != FLAG_TYPE) {
		print_error("-c | -o | -e operation only for the flag type");
		goto out;
	}

	if (opr_type < CLEAR_FLAG || opr_type >  TOGGLE_FLAG) {
		print_error("Incorrect operation for the flag type");
		goto out;
	}

	options->opr = opr_type;
	return OK;

out:
	return ERROR;
}

