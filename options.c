// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2018 Western Digital Corporation

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <errno.h>

#include "options.h"
#include "ufs.h"

static int verify_and_set_idn(struct tool_options *options);
static int verify_read(struct tool_options *options);
static int verify_write(struct tool_options *options);
static int verify_and_set_flag_operation(int opr_type,
		struct tool_options *options);
static int verify_and_set_device_path(struct tool_options *options);
static int verify_arg_and_set_default(struct tool_options *options);
static int verify_and_set_index(struct tool_options *options);

int init_options(int opt_cnt, char *opt_arr[], struct tool_options *options)
{
	int rc = INVALID;
	int curr_opt = 0;

	while (-1 != (curr_opt =
		getopt(opt_cnt, opt_arr,
		"t:p:w:i:rocea"))) {
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
			rc = verify_and_set_flag_operation(CLEAR_FLAG, options);
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

		default:
			rc = INVALID;
			break;
		}
		if (rc)
			break;
	}
	if (!rc)
		rc = verify_arg_and_set_default(options);
	return rc;
}

static int verify_and_set_index(struct tool_options *options)
{
	int index = INVALID;

	if (options->index != INVALID) {
		print_error("duplicated index");
		return ERROR;
	}
	/* In case atoi returned 0 . Check that is real 0
	 * and not error arguments . Also check that the value
	 * is in correct range*/
	index = atoi(optarg);
	if (optarg == NULL ||
		(index == 0 && (strcmp(optarg, "0")) != 0) ||
		((index < 0))) {
		print_error("Invalid argument for index");
		return ERROR;
	}
	options->index = index;
	return OK;
}

static int verify_and_set_idn(struct tool_options *options)
{
	int idn = INVALID;

	if (options->idn != INVALID) {
		print_error("duplicated desc type option");
		return ERROR;
	}
	/* In case atoi returned 0. Check that is real 0
	 * and not error arguments. Also check that the value
	 * is in correct range*/
	idn = atoi(optarg);
	if (optarg == NULL ||
		(idn == 0 && (strcmp(optarg, "0")) != 0) ||
		((idn < 0))) {
		print_error("Invalid argument for idn");
		return ERROR;
	}

	switch (options->config_type_inx) {
	case DESC_TYPE:
		if (idn > QUERY_DESC_IDN_MAX) {
			print_error("Invalid descriptor idn %d", idn);
			return ERROR;
		}
		break;
	case ATTR_TYPE:
		if (idn >= QUERY_ATTR_IDN_MAX) {
			print_error("Invalid attr idn %d", idn);
			return ERROR;
		}
		break;
	case FLAG_TYPE:
		if (idn > QUERY_FLAG_IDN_PERMANENTLYDISABLEFW) {
			print_error("Invalid flag idn %d", idn);
			return ERROR;
		}
		break;
	default:
		print_error("Invalid UFS configuration type %d", idn);
		return ERROR;
	}
	if (options->idn != INVALID) {
		print_error("duality option for the idn");
		return ERROR;
	}
	options->idn = idn;

	return OK;
}

static int verify_arg_and_set_default(struct tool_options *options)
{
	if (options->path[0] == '\0') {
		print_error("Missing device path type");
		return ERROR;
	}

	if ((options->opr == INVALID) &&
		(options->config_type_inx != DESC_TYPE))
		options->opr = READ;

	if ((options->opr == INVALID) &&
		(options->config_type_inx == DESC_TYPE)) {
		print_error("The operation is missed");
		return ERROR;
	}

	if ((options->opr == WRITE) && (options->data == NULL)) {
		print_error("Data missed for the write operation");
		return ERROR;
	}

	if (options->opr != READ_ALL && options->idn == INVALID) {
		print_error("The type idn is missed");
		return ERROR;
	}

	if ((options->config_type_inx == DESC_TYPE) &&
		(options->idn == QUERY_DESC_IDN_STRING) &&
		(options->index == INVALID)) {
		print_error("The index is missed");
		return ERROR;
	}

	if (options->index == INVALID)
		options->index = 0;

	return OK;
}

static int verify_and_set_device_path(struct tool_options *options)
{
	if (options->path[0] != '\0') {
		print_error("Duplicate Device path");
		return ERROR;
	}

	if ((optarg == NULL) || (optarg[0] == 0)) {
		print_error("Device path missed");
		return ERROR;
	}

	if (strlen(optarg) >= MAX_DEVICE_PATH_LEN) {
		print_error("Device path is too long");
		return ERROR;
	}

	strcpy(options->path, optarg);
	return OK;
}

static int verify_read(struct tool_options *options)
{
	if (options->opr != INVALID) {
		print_error("duplicated operation option(read) 2%d",
			options->opr);
		return ERROR;
	}

	if (options->config_type_inx == DESC_TYPE) {
		print_error("Currently Read is unsupported for descriptor, "
			"due to bsg driver limitation");
		return ERROR;
	}
	return OK;
}

static int verify_write(struct tool_options *options)
{
	char *endptr;

	errno = 0;

	if (options->opr != INVALID)
		print_error("duplicated operation option(write)");

	if ((optarg == NULL) || (optarg[0] == 0)) {
		print_error("Data is missed");
		return ERROR;
	}

	if (options->config_type_inx == DESC_TYPE) {
		if ((options->idn != QUERY_DESC_IDN_CONFIGURAION) &&
		(options->idn != QUERY_DESC_IDN_STRING)) {
			print_error("write is unavailable for"
				"descriptor type = %d",
				options->idn);
			return ERROR;
		}
		if (strlen(optarg) >= QUERY_DESC_STRING_MAX_SIZE) {
			print_error("Input data is too big");
			return ERROR;
		}
		options->data = (char *)malloc(QUERY_DESC_STRING_MAX_SIZE);
		if (options->data == NULL) {
			print_error("Memory Allocation problem");
			return ERROR;
		}
		strcpy(options->data, optarg);
	}

	if (options->config_type_inx == FLAG_TYPE) {
		print_error("Please use 'c', 'e', or 'o' for flag operations");
		return ERROR;
	}

	if (options->config_type_inx == ATTR_TYPE) {
		options->data = (__u32 *)calloc(1, sizeof(__u32));
		*(__u32 *)options->data = strtol(optarg, &endptr, 16);
		if ((errno != 0) || (*endptr != '\0')) {
			print_error("Wrong data");
			return ERROR;
		}
	}

	return OK;
}

static int verify_and_set_flag_operation
	(int opr_type, struct tool_options *options)
{
	if (options->opr != INVALID)
		print_error("duplicated operation option");

	if (options->config_type_inx != FLAG_TYPE) {
		print_error("-c | -o | -e operation only for the flag type");
		return ERROR;
	}

	if (opr_type < CLEAR_FLAG || opr_type >  TOGGLE_FLAG) {
		print_error("Incorrect operation for the flag type");
		return ERROR;
	}
	options->opr = opr_type;

	return OK;
}

