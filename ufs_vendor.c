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

#include "ufs.h"
#include "ufs_cmds.h"
#include "options.h"
#include "options.h"
#include "scsi_bsg_util.h"
#include "ufs_vendor.h"

static int write_data(struct tool_options *opt, int dev_fd, void *p_data);
static int read_data(struct tool_options *opt, int dev_fd, void *p_data);

int do_vendor(struct tool_options *opt)
{
	int rc = INVALID;
	int fd;
	void *p_data;

	WRITE_LOG("Start : %s", __func__);
	p_data = malloc(opt->len);
	if (!p_data) {
		print_error("Cannot allocate %d Bytes", opt->len);
		return ERROR;
	}

	fd = open(opt->path, O_RDWR | O_SYNC);
	if (fd < 0) {
		perror("Device open");
		goto out;
	}

	if (opt->opr == WRITE)
		rc = write_data(opt, fd, p_data);
	else
		rc = read_data(opt, fd, p_data);
out:
	free(p_data);

	if (fd != INVALID)
		close(fd);

	return rc;
}

static int write_data(struct tool_options *opt, int dev_fd, void *p_data)
{
	int input_fd;
	int rc = INVALID;
	off_t file_size;

	input_fd = open(opt->data, O_RDONLY | O_SYNC);
	if (input_fd < 0) {
		perror("Input file open");
		return ERROR;
	}

	file_size = lseek(input_fd, 0, SEEK_END);
	if ((file_size <= 0) || (file_size < opt->len)) {
		print_error("Wrong input data file length = %d",
			    file_size);
		goto out;
	}
	lseek(input_fd, 0, SEEK_SET);

	if (read(input_fd, p_data, opt->len) != opt->len) {
		print_error("Read %d data bytes from input file failed",
			opt->len);
		goto out;
	}
	rc = write_buffer(dev_fd, p_data, BUFFER_VENDOR_MODE, opt->index,
			  opt->offset, opt->len, opt->sg_type);
	if (!rc)
		printf("The vendor buffer was written\n");
out:
	close(input_fd);
	return rc;
}

static int read_data(struct tool_options *opt, int dev_fd, void *p_data)
{
	int rc = INVALID;

	rc = read_buffer(dev_fd, p_data, BUFFER_VENDOR_MODE, opt->index,
			 opt->offset, opt->len, opt->sg_type);
	if (!rc) {
		write_file("read_vendor_buffer.dat", p_data, opt->len);
		printf("read_vendor_buffer.dat created\n");
	}

	return rc;
}

void vendor_help(char *tool_name)
{
	printf("\n Vendor Write/Read Buffer command usage:\n");
	printf("\n\t%s vendor [-r ][-w] <path to data file> [-L] <data_len>\n"
		"\t\t[-O] <buf offset> [-p] <path to device>\n",
		tool_name);
	printf("\n\t-r\tRead vendor buffer command[default operation]\n");
	printf("\n\t-w\tInput file path for write buffer vendor command\n");
	printf("\n\t-L\tData buffer length, up to 512 Bytes[default value 512B]\n");
	printf("\n\t-i\tBuffer ID\n");
	printf("\n\t-g\t sg struct ver - 0: SG_IO_VER4 (default), 1: SG_IO_VER3\n");
	printf("\n\t-O\tBuffer Offset\n");
	printf("\n\t-p\tDevice path\n");
}
