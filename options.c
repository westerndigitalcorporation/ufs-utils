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
#include "ufs_ffu.h"
#include "ufs_rpmb.h"
#include "ufs_hmr.h"

char gl_pr_type = VERBOSE;

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
static int verify_and_set_ffu_chunk_size(struct tool_options *options);
static int verify_length(struct tool_options *options);
static int verify_offset(struct tool_options *options);
static int verify_and_set_start_addr(struct tool_options *options);
static int verify_and_set_num_block(struct tool_options *options);
static int verify_lun(struct tool_options *options);
static int verify_and_set_key_path(struct tool_options *options);
static int verify_region(struct tool_options *options);
static int verify_and_set_hmr_method(struct tool_options *options);
static int verify_and_set_hmr_unit(struct tool_options *options);
static int verify_sg_struct(struct tool_options *options);
static int verify_output_data(struct tool_options *options);
static int verify_output_mode(struct tool_options *options);

#define MAX_ADDRESS 0xFFFF


int init_options(int opt_cnt, char *opt_arr[], struct tool_options *options)
{
	int rc = -EINVAL;
	int curr_opt = 0;
	int opt = 0;

	static struct option long_opts[] = {
		{"peer", no_argument, NULL, 'u'}, /* UFS device */
		{"local", no_argument, NULL, 'l'}, /* UFS host*/
		/* output file for the descriptor file store */
		{"output_file", required_argument, NULL, 'D'},
		{"output_mode", required_argument, NULL, 'P'},
		{NULL, 0, NULL, 0}
	};
	static char *short_opts = "t:p:w:i:s:O:L:n:k:m:d:x:y:g:D:P:rocea";

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
			if (options->config_type_inx == FFU_TYPE)
				rc = verify_and_set_ffu_chunk_size(options);
			else if (options->config_type_inx == RPMB_CMD_TYPE)
				rc = verify_and_set_start_addr(options);
			else
				rc = verify_and_set_selector(options);
			break;
		case 'u':
			rc = verify_target(options, DME_PEER);
			break;
		case 'l':
			rc = verify_target(options, DME_LOCAL);
			break;
		case 'd':
			rc = verify_lun(options);
			break;
		case 'L':
			rc = verify_length(options);
			break;
		case 'O':
			rc = verify_offset(options);
			break;
		case 'n':
			rc = verify_and_set_num_block(options);
			break;
		case 'k':
			rc = verify_and_set_key_path(options);
			break;
		case 'm':
			rc = verify_region(options);
			break;
		case 'x':
			rc = verify_and_set_hmr_method(options);
			break;
		case 'y':
			rc = verify_and_set_hmr_unit(options);
			break;
		case 'g':
			rc = verify_sg_struct(options);
			break;
		case 'D':
			rc = verify_output_data(options);
			break;
		case 'P':
			rc = verify_output_mode(options);
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

	if ((index == 0 && strcmp(optarg, "0")) || index < 0) {
		print_error("Invalid argument for index");
		goto out;
	}

	options->index = index;
	return OK;

out:
	return ERROR;
}

static int verify_and_set_ffu_chunk_size(struct tool_options *options)
{
	int chunk_size_kb =  atoi(optarg);

	if (!chunk_size_kb) {
		print_error("Invalid chunk_size %d ", chunk_size_kb);
		goto out;
	}
	options->size = chunk_size_kb * 1024;
	if ((options->size > MAX_IOCTL_BUF_SIZE) ||
		(options->size % ALIGNMENT_CHUNK_SIZE)) {
		print_error("The chunk should be multiple value of 4k, between 4k and %dk",
				MAX_IOCTL_BUF_SIZE / 1024);
		goto out;
	}
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
	if ((selector == 0 && strcmp(optarg, "0")) || selector < 0) {
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
		print_error("duplicated type option");
		goto out;
	}

	/* In case atoi returned 0. Check that is real 0 and not error
	 * arguments. Also check that the value is in correct range
	 */
	idn = atoi(optarg);
	if ((idn == 0 && strcmp(optarg, "0")) || idn < 0) {
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
	case FLAG_TYPE:
		break;
	case UIC_TYPE:
		if (idn >= MAX_UNIPRO_IDN) {
			print_error("Invalid UIC idn %d", idn);
			goto out;
		}
		break;
	case FFU_TYPE:
		if (idn >= UFS_FFU_MAX) {
			print_error("Invalid ffu cmd %d", idn);
			goto out;
		}
		break;
	case RPMB_CMD_TYPE:
		if (idn >= RPMB_CMD_MAX) {
			print_error("Invalid rpmb cmd %d", idn);
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

static int verify_length(struct tool_options *options)
{
	int len = INVALID;

	if (options->len != INVALID) {
		print_error("duplicated length option");
		goto out;
	}

	/* In case atoi returned 0. Check that is real 0 and not error
	 * arguments. Also check that the value is in correct range
	 */
	len = atoi(optarg);
	if (len == 0 || len < 0 || len > BLOCK_SIZE) {
		print_error("Invalid argument for length. The value should be between 1 to %dB",
				BLOCK_SIZE);
		goto out;
	}

	options->len = len;
	return OK;

out:
	return ERROR;
}

static int verify_offset(struct tool_options *options)
{
	int offset = INVALID;

	if (options->offset != INVALID) {
		print_error("duplicated offset option");
		goto out;
	}
	if (strstr(optarg, "0x") || strstr(optarg, "0X"))
		offset = (int)strtol(optarg, NULL, 0);
	else
		offset = atoi(optarg);
	if ((offset == 0 && strcmp(optarg, "0")) || offset < 0) {
		print_error("Invalid argument for offset");
		goto out;
	}

	options->offset = offset;
	return OK;

out:
	return ERROR;
}

static int verify_and_set_start_addr(struct tool_options *options)
{
	int start_block = 0;

	if (options->config_type_inx != RPMB_CMD_TYPE) {
		print_error("start block address using only for rpmb cmd");
		goto out;
	}

	start_block = atoi(optarg);
	if ((start_block == 0 && strcmp(optarg, "0")) ||
	     start_block < 0 || start_block > MAX_ADDRESS) {
		print_error("Invalid start address");
		goto out;
	} else
		options->start_block = start_block;
	return OK;

out:
	return ERROR;
}

static int verify_and_set_num_block(struct tool_options *options)
{
	int num_block = 0;

	if (options->config_type_inx != RPMB_CMD_TYPE) {
		print_error("num_block using only for rpmb cmd");
		goto out;
	}

	num_block = atoi(optarg);
	if ((num_block == 0 && strcmp(optarg, "0")) || num_block < 0) {
		print_error("Invalid numbers of block");
		goto out;
	} else
		options->num_block = num_block;
	return OK;

out:
	return ERROR;

}

static int verify_and_set_key_path(struct tool_options *options)
{
	if (options->config_type_inx != RPMB_CMD_TYPE) {
		print_error("key path using only for rpmb cmd");
		goto out;
	}

	if (options->keypath[0] != '\0') {
		print_error("Duplicate Key path");
		goto out;
	}

	if ((optarg == NULL) || (optarg[0] == 0)) {
		print_error("Key path missed");
		goto out;
	}

	if (strlen(optarg) >= PATH_MAX) {
		print_error("Key path is too long");
		goto out;
	}

	strcpy(options->keypath, optarg);
	return OK;

out:
	return ERROR;
}

static int verify_sg_struct(struct tool_options *options)
{
	int8_t sg_type;

	if ((0 == (sg_type = atoi(optarg)) && 0 != (strcmp(optarg, "0"))) ||
		((sg_type != SG3_TYPE) && (sg_type != SG4_TYPE))) {
			print_error("Invalid SG struct");
			return ERROR;
	} else
		options->sg_type = sg_type;
	return OK;
}

static int verify_lun(struct tool_options *options)
{
	int8_t lun = 0;

	lun = atoi(optarg);
	if ((lun == 0 && strcmp(optarg, "0")) || lun < 0) {
		print_error("Invalid lun");
		return ERROR;
	}
	options->lun = lun;
	return OK;
}

static int verify_region(struct tool_options *options)
{
	int8_t region = 0;

	region = atoi(optarg);
	if ((region == 0 && strcmp(optarg, "0")) || region < 0
		|| region > 3) {
		print_error("Invalid RPMB region");
		return ERROR;
	}
	options->region = region;
	return OK;
}

static int verify_rpmb_arg(struct tool_options *options)
{
	int ret = OK;

	if (options->region == INVALID)
		options->region = 0;

	switch (options->idn) {
	case AUTHENTICATION_KEY:
		if (options->keypath[0] == 0) {
			print_error("Key path is missed");
			ret = ERROR;
		}
	break;
	case READ_RPMB:
		if (!options->data) {
			print_error("Output data file missed");
			ret = ERROR;
		}
	break;
	case READ_SEC_RPMB_CONF_BLOCK:
		if (!options->data) {
			print_error("Output data file missed");
			ret = ERROR;
		}
		if (options->lun == INVALID) {
			print_error("LUN parameter is missed");
			ret = ERROR;
		}

		if (options->region > 0) {
			print_error("Config block exist only in region 0");
			ret = ERROR;
		}
	break;
	case WRITE_RPMB:
		if (!options->data) {
			print_error("Input data file missed");
			ret = ERROR;
		}
		if (options->keypath[0] == 0) {
			print_error("Key path is missed");
			ret = ERROR;
		}
		if (options->num_block == INVALID)
			options->num_block = 1;
		if (options->start_block == INVALID)
			options->start_block = 0;
	break;
	case WRITE_SEC_RPMB_CONF_BLOCK:
		if (!options->data) {
			print_error("Input data file missed");
			ret = ERROR;
		}
		if (options->keypath[0] == 0) {
			print_error("Key path is missed");
			ret = ERROR;
		}
		if (options->region > 0) {
			print_error("Config block exist only in region 0");
			ret = ERROR;
		}
	break;
	case READ_WRITE_COUNTER:
	break;
	default:
		print_error("Unsupported RPMB cmd %d",
			    options->idn);
	break;
	}
	return ret;
}

static int verify_and_set_hmr_method(struct tool_options *options)
{
	int ret = ERROR;
	long result;

	if (options->hmr_method != INVALID) {
		print_error("Duplicated hmr method option");
		goto out;
	}

	ret = str_to_long(optarg, 10, &result);
	if (ret == ERROR) {
		print_error("Invalid argument for hmr method: not convertable");
		goto out;
	}

	if (result < HMR_METHOD_FORCE || result >= HMR_METHOD_MAX) {
		print_error("Invalid argument for hmr method: out of range");
		ret = ERROR;
		goto out;
	}

	options->hmr_method = result;

out:
	return ret;
}

static int verify_and_set_hmr_unit(struct tool_options *options)
{
	int ret = ERROR;
	long result;

	if (options->hmr_unit != INVALID) {
		print_error("Duplicated hmr unit option");
		goto out;
	}

	ret = str_to_long(optarg, 10, &result);
	if (ret == ERROR) {
		print_error("Invalid argument for hmr unit: not convertable");
		goto out;
	}

	if (result < HMR_UNIT_MIN || result >= HMR_UNIT_MAX) {
		print_error("Invalid argument for hmr unit: out of range");
		ret = ERROR;
		goto out;
	}

	options->hmr_unit = result;

out:
	return ret;
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
	if (options->config_type_inx != ERR_HIST_TYPE &&
	    options->config_type_inx != VENDOR_BUFFER_TYPE &&
	    options->config_type_inx != HMR_TYPE &&
	    options->config_type_inx != SPEC_VERSION &&
	    options->opr != READ_ALL &&
	    options->idn == INVALID) {
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

	if (options->config_type_inx == FFU_TYPE) {
		if (options->size == INVALID)
			options->size = DEFAULT_IOCTL_BUF_SIZE;
		if (options->idn == INVALID)
			/*Default operation*/
			options->idn = UFS_FFU;
		if ((options->idn != UFS_CHECK_FFU_STATUS) &&
			(options->data == NULL)) {
			print_error("The FW file name is missing");
			goto out;
		}
	}

	if ((options->config_type_inx == VENDOR_BUFFER_TYPE) &&
	    (options->len == INVALID))
		options->len = BLOCK_SIZE;

	if (options->config_type_inx == RPMB_CMD_TYPE) {
		if (verify_rpmb_arg(options))
			goto out;
	}

	if (options->config_type_inx == HMR_TYPE) {
		if (options->hmr_method == INVALID)
			options->hmr_method = HMR_METHOD_SELECTIVE;

		if (options->hmr_unit == INVALID)
			options->hmr_unit = HMR_UNIT_MIN;
	}

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

	if (optarg[0] == 0) {
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
		print_error("duplicated operation option(read)");
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

	if (optarg[0] == 0) {
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
		if (!options->data)
			goto out_mem_problem;

		strcpy(options->data, optarg);
	}

	if (options->config_type_inx == FLAG_TYPE) {
		print_error("Please use 'c', 'e', or 'o' for flag operations");
		goto out;
	}

	if (options->config_type_inx == ATTR_TYPE ||
	    options->config_type_inx == UIC_TYPE) {
		options->data = (__u32 *)calloc(1, sizeof(__u32));
		if (!options->data)
			goto out_mem_problem;

		*(__u32 *)options->data = strtol(optarg, &endptr, 16);

		if (errno != 0 || *endptr != '\0') {
			print_error("Wrong data");
			goto out;
		}
	}
	if (options->config_type_inx == FFU_TYPE ||
	    options->config_type_inx == VENDOR_BUFFER_TYPE ||
	    options->config_type_inx == RPMB_CMD_TYPE) {
		int len = strlen(optarg) + 1;

		if (len >= PATH_MAX) {
			print_error("Input file path is too long");
			goto out;
		}
		options->data = (char *)calloc(1, len);
		if (options->data == NULL)
			goto out_mem_problem;
		else
			strcpy(options->data, optarg);
	}

	return OK;

out_mem_problem:
	print_error("Memory Allocation problem");
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

static int verify_output_data(struct tool_options *options)
{
	int len;

	if (options->data != 0) {
		print_error("Duplicate Output path %d",
			    options->data);
		goto out;
	}

	if (optarg == 0) {
		print_error("Output path missed");
		goto out;
	}

	len = strlen(optarg);
	if (len >= PATH_MAX) {
		print_error("Output path is too long");
		goto out;
	}

	options->data = (char *)calloc(1, len);
	if (!options->data) {
		print_error("Memory Allocation problem");
		goto out;
	}

	strcpy(options->data, optarg);
	return OK;

out:
	return ERROR;
}

static int verify_output_mode(struct tool_options *options)
{
	if (!strcmp(optarg, "raw")) {
		gl_pr_type = RAW_VALUE;
	} else if (!strcmp(optarg, "json")) {
		gl_pr_type = JSON;
	} else if (!strcmp(optarg, "verbose")) {
		gl_pr_type = VERBOSE;
	} else {
		print_error("Wrong output mode");
		return ERROR;
	}

	return OK;
}
