// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2019 Western Digital Corporation or its affiliates */

/*
 * UFS3.0(UFSv3.0 JESD220D spec.) allows to retrieve the error history by using
 * the READ BUFFER command.
 */

#include "ufs_err_hist.h"

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
#include "ioctl.h"

#define MIN(a, b) (((a) < (b))?(a):(b))
#define MAX(a, b) (((a) > (b))?(a):(b))

/*
 * The spec actualy says: "and ALLOCATION LENGTH set to at least 2088
 * (i.e., large enough to transfer the complete error history directory)."
 * This is apparently an error because it doesn't adds up to the entries
 * count and sizes: The error history header is 32bytes, and there can be
 * up to (0xEF – 0x10 + 1) = 224 entries. Each entry is 8bytes, so the
 * directory should weight 224*8 + 32 = 1824bytes, and not 2088.
 */
#define EHS_DIR_ALLOC_LEN 1824
/* According to the spec, BUF ID can be between 0x10 0xEF range */
#define EHS_MIN_BUF_ID 0x10
#define EHS_MAX_BUF_ID 0xEF
#define EHS_MAX_ENTRIES (EHS_MAX_BUF_ID - EHS_MIN_BUF_ID + 1)
/* 3 bytes for Allocation Length field + 3 bytes for Buffer offset field*/
#define READ_BUF_MAX_AVAIL_LEN (0xFFFFFF + 0xFFFFFF)
#define BLOCKS_IN_FAD_BLOCK (MAX_IOCTL_BUF_SIZE / BLOCK_SIZE)

struct ehs_directory_entry {
	u_int8_t buffer_id;
	u_int8_t reserved[3];
	u_int32_t length;
};

struct ehs_directory_header {
	u_int8_t vendor_id[8];
	u_int8_t version;
	u_int8_t reserved1;
	u_int8_t reserved2[20];
	u_int16_t length;
};

struct ehs_directory_buffer {
	struct ehs_directory_header hdr;
	struct ehs_directory_entry entries[EHS_MAX_ENTRIES];
};

static inline int write_single_fad(const int file, const void *buffer, int sz)
{
	if (write(file, buffer, sz) !=  sz)
		return -EIO;
	else
		return 0;
}

static int log_ehs_buffer(int fd, int file, __u8 *buf, __u8 buf_id,
			  __u32 len)
{
	int rc = -EINVAL;
	__u32 sent = 0;
	int i = 0;

	printf("\nPlease wait for error history extraction\n");
	while (sent < len) {
		__u32 ofst = i * MAX_IOCTL_BUF_SIZE;
		__u32 sz =
			(len - sent >= MAX_IOCTL_BUF_SIZE) ? MAX_IOCTL_BUF_SIZE :
							(len - sent);

		rc = read_buffer(fd, buf, BUFFER_EHS_MODE, buf_id, ofst, sz);
		if (rc) {
			print_error("read_buffer buff_id 0x%x fad %d",
				buf_id, i);
			goto out;
		}

		rc = write_single_fad(file, buf, sz);
		if (rc) {
			print_error("write buf_id 0x%x fad %d", buf_id, i);
			goto out;
		}

		sent += sz;
		i++;
		memset(buf, 0x0, MAX_IOCTL_BUF_SIZE);
	}

	rc = 0;
out:
	return rc;
}

static int log_error_history(int fd, struct ehs_directory_entry *entries,
			__u8 buffers_cnt)
{
	int file;
	__u8 *buf = NULL;
	int rc = -EINVAL;
	int i;

	file = open("error_history.dat", O_RDWR | O_CREAT | O_TRUNC | O_SYNC,
		S_IWUSR | S_IRUSR);
	if (file == -1) {
		perror("open");
		goto out;
	}

	/* IO size is limited by max_sectors_kb which is usually 512k - set a
	 * slightly smaller chunk - 256k.
	 */
	buf = calloc(1, MAX_IOCTL_BUF_SIZE);
	if (!buf) {
		rc = -ENOMEM;
		goto out;
	}

	for (i = 0; i < buffers_cnt; i++) {
		struct ehs_directory_entry *entry = entries + i;
		u_int8_t buf_id = entry->buffer_id;
		u_int32_t len = be32toh(entry->length);

		if (buf_id < EHS_MIN_BUF_ID || buf_id > EHS_MAX_BUF_ID) {
			print_error("illegal buffer id 0x%x entry %d",
				buf_id, i);
			goto out;
		}

		if (!len || len > READ_BUF_MAX_AVAIL_LEN) {
			print_error("illegal len 0x%x entry %d", len, i);
			goto out;
		}

		rc = log_ehs_buffer(fd, file, buf, buf_id, len);
		if (rc) {
			print_error("log_ehs_buffer buffer id 0x%x", buf_id);
			goto out;
		}
	}

	rc = 0;
out:
	if (buf)
		free(buf);

	if (file != -1)
		close(file);
	return rc;
}

static int decode_ehs_directory(struct ehs_directory_buffer *ehs_dir,
				__u8 *buffers_cnt)
{
	int rc = -EINVAL;
	u_int16_t length = 0;

	if (!ehs_dir)
		goto out;

	length = be16toh(ehs_dir->hdr.length);
	if (!length || length % sizeof(struct ehs_directory_entry)) {
		print_error("Illegal directory length 0x%x", length);
		goto out;
	}

	*buffers_cnt = length / sizeof(struct ehs_directory_entry);
	if (*buffers_cnt > EHS_MAX_ENTRIES) {
		print_error("Illegal buffers count %d", *buffers_cnt);
		goto out;
	}

	rc = 0;
out:
	return rc;
}

int do_err_hist(struct tool_options *opt)
{
	int rc = INVALID;
	int fd;
	__u8 *ehs_buf = NULL;
	struct ehs_directory_buffer *ehs_dir = NULL;
	__u8 ehs_buffer_cnt = 0;

	fd = open(opt->path, O_RDWR | O_SYNC);
	if (fd < 0) {
		perror("open");
		return ERROR;
	}

	WRITE_LOG("Start : %s cmd type %d", __func__, opt->idn);
	ehs_buf = calloc(1, EHS_DIR_ALLOC_LEN);
	if (!ehs_buf) {
		rc = -ENOMEM;
		goto out;
	}

	rc = read_buffer(fd, ehs_buf, BUFFER_EHS_MODE, 0, 0,
			EHS_DIR_ALLOC_LEN);
	if (rc)
		goto out;

	rc = write_file("error_history_directory.dat", ehs_buf,
			EHS_DIR_ALLOC_LEN);
	if (rc)
		goto out;

	printf("error_history_directory.dat is created\n");

	ehs_dir = (struct ehs_directory_buffer *)ehs_buf;
	rc = decode_ehs_directory(ehs_dir, &ehs_buffer_cnt);
	if (rc)
		goto out;

	printf("retrieving error history, this may take a while\n\n");
	rc = log_error_history(fd, ehs_dir->entries, ehs_buffer_cnt);
	if (rc)
		goto out;

	printf("\nerror_history.dat is created\n");

out:
	if (ehs_buf)
		free(ehs_buf);
	close(fd);

	return rc;
}

void err_hist_help(char *tool_name)
{
	printf("\n Error history command usage:\n");
	printf("\n\t%s err_hist [-p] <path to device> \n", tool_name);
	printf("\n\t-p\tPath to the bsg device\n");
}
