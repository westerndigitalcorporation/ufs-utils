// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2019 Western Digital Corporation or its affiliates */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdint.h>
#include <errno.h>
#include <asm-generic/int-ll64.h>

#include "ufs.h"
#include "ufs_cmds.h"
#include "options.h"
#include "ioctl.h"
#include "ufs_ffu.h"
#include "scsi_bsg_util.h"

#define DEVICE_VERSION_OFFSET 0x1E
#define FFU_STATUS_ATTR 0x14

enum ffu_status_type {
	NO_INFORMATION,
	SUCCESSFUL_MICROCODE_UPDATE,
	MICROCODE_CORRUPTION_ERROR,
	INTERNAL_ERROR,
	MICROCODE_VERSION_MISMATCH,
	GENERAL_ERROR = 0xFF
};


extern int do_query_rq(int fd, struct ufs_bsg_request *bsg_req,
		struct ufs_bsg_reply *bsg_rsp, __u8 query_req_func,
		__u8 opcode, __u8 idn, __u8 index, __u8 sel,
		__u16 req_buf_len, __u16 res_buf_len, __u8 *data_buf);
extern struct desc_field_offset device_desc_field_name[];

/* Get sense key string or NULL if not available */
static const char *
ffu_status_string(enum ffu_status_type status)
{
	switch (status) {
	case NO_INFORMATION:
		return "NO INFORMATION";
	break;
	case SUCCESSFUL_MICROCODE_UPDATE:
		return "SUCCESSFUL MICROCODE UPDATE";
	break;
	case INTERNAL_ERROR:
		return "INTERNAL ERROR";
	break;
	case MICROCODE_CORRUPTION_ERROR:
		return "MICROCODE CORRUPTION ERROR";
	break;
	case GENERAL_ERROR:
		return "GENERAL ERROR";
	break;
	default:
		return "UNSUPPORTED STATUS";
	break;
	}
	return 0;
}

static int flash_ffu(int fd, struct tool_options *opt)
{
	int rc = INVALID;
	int input_fd = INVALID;
	off_t file_size;
	__u8 *p_data = NULL;
	uint32_t chunk_size = opt->size;
	uint32_t buf_offset = 0;
	uint32_t write_buf_count;

	input_fd = open(opt->data, O_RDONLY | O_SYNC);
	if (input_fd < 0) {
		perror("Input file open");
		goto out;
	}

	file_size = lseek(input_fd, 0, SEEK_END);
	/* The FFU file shall be aligned to 4k */
	if ((file_size <= 0) || (file_size % ALIGNMENT_CHUNK_SIZE)) {
		print_error("Wrong FFU file");
		goto out;
	}
	lseek(input_fd, 0, SEEK_SET);
	p_data = calloc(file_size, sizeof(__u8));
	if (!p_data) {
		print_error("Cannot allocate FFU size %d", file_size);
		goto out;
	}
	if (read(input_fd, (char *)p_data, file_size) !=
			file_size) {
			print_error("Read FFU is failed");
			goto out;
	}

	while (file_size > 0) {
		if (file_size > chunk_size)
			write_buf_count = chunk_size;
		else
			write_buf_count = file_size;
		rc = write_buffer(fd, p_data + buf_offset, BUFFER_FFU_MODE, 0,
			buf_offset, write_buf_count, opt->sg_type);
		if (rc) {
			print_error("Write error %d:", rc);
			goto out;
		}
		buf_offset = buf_offset + write_buf_count;
		file_size = file_size - write_buf_count;
	}

	sync();
	printf("\nFFU was written to the device, reboot and check status\n");

out:
	if (input_fd != INVALID)
		close(input_fd);
	if (p_data)
		free(p_data);
	return rc;

}

static int check_ffu_status(int fd, struct tool_options *opt)
{
	int rc = ERROR;
	__u8 dev_desc[QUERY_DESC_DEVICE_MAX_SIZE] = {0};
	struct ufs_bsg_request bsg_req = {0};
	struct ufs_bsg_reply bsg_rsp = {0};
	__u32 attr_value;
	__u16 *ufs_feature_support;
	struct desc_field_offset *tmp = &device_desc_field_name[DEVICE_VERSION_OFFSET];

	rc = do_query_rq(fd, &bsg_req, &bsg_rsp,
			UPIU_QUERY_FUNC_STANDARD_READ_REQUEST,
			UPIU_QUERY_OPCODE_READ_ATTR, FFU_STATUS_ATTR,
			0, 0, 0, 0, 0);
	if (rc) {
		print_error("Warning cannot read bDeviceFFUStatus attribute status\n");
		goto out;
	}

	else {
		attr_value = be32toh(bsg_rsp.upiu_rsp.qr.value);
		printf("%-20s := 0x%02x (%s)\n", "bDeviceFFUStatus",
			attr_value,
			ffu_status_string((enum ffu_status_type)attr_value));
	}

	rc = do_device_desc(fd, (__u8 *)&dev_desc);
	if (rc != OK)
		print_error("Could not read device descriptor in order to "
			"read device version\n");
	else {
		ufs_feature_support = (__u16 *)&dev_desc[tmp->offset];
		printf("%s = 0x%x\n", tmp->name, *ufs_feature_support);
	}
out:
	return rc;
}

int do_ffu(struct tool_options *opt)
{
	int rc = INVALID;
	int fd = INVALID;

	fd = open(opt->path, O_RDWR | O_SYNC);
	if (fd < 0) {
		perror("open");
		exit(1);
	}

	switch (opt->idn) {
	case UFS_FFU:
		rc = flash_ffu(fd, opt);
		break;
	case UFS_CHECK_FFU_STATUS:
		rc = check_ffu_status(fd, opt);
		break;
	default:
		print_error("Unsupported FFU type operation");
		break;
	}

	close(fd);
	return rc;
}

void ffu_help(char *tool_name)
{
	printf("\n FFU command usage:\n");
	printf("\n\t%s ffu [-t] <ffu cmd idn> [-p] <path to device> \n",
		tool_name);
	printf("\n\t-t\t FFU cmd idn\n");
	printf("\t\t\t %-3d: %-25s\n",
		UFS_FFU,
		"FFU, flash FFU");
	printf("\t\t\t %-3d: %-25s\n",
		UFS_CHECK_FFU_STATUS,
		"Check FFU status (check FFU status attribute and display FW version)");
	printf("\n\t-s\t Max chunk size in KB alignment to 4KB, "
		"which FFU file will be split (optional)\n");
	printf("\n\t-w\t path to FFU file\n");
	printf("\n\t-g\t sg struct ver - 0: SG_IO_VER4 (default), 1: SG_IO_VER3\n");
	printf("\n\t-p\t bsg device path for FFU, ufs-bsg for Check FFU status\n");
}
