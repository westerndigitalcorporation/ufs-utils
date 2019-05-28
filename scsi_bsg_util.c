// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2019 Western Digital Corporation or its affiliates */

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <stdint.h>
#include <fcntl.h>
#include <unistd.h>

#include "ioctl.h"
#include "ufs.h"
#include "scsi_bsg_util.h"

#define UPIU_HEADER_DWORD(byte3, byte2, byte1, byte0)\
			htobe32((byte3 << 24) | (byte2 << 16) |\
				(byte1 << 8) | (byte0))

#ifdef DEBUG
static int write_file(const char *name, const void *buffer, int length)
{
	int fd;
	int rc = 0;
	size_t ret;

	WRITE_LOG("writing file %s length=%d\n", name, length);
	fd = open(name, O_RDWR | O_CREAT | O_TRUNC | O_SYNC, 0600);
	if (fd == -1) {
		WRITE_LOG("%s: failed in open errno=%d", __func__, errno);
		return -ENOENT;
	}

	ret = write(fd, buffer, length);
	if (length != ret) {
		WRITE_LOG("%s: failed in write errno=%d", __func__, errno);
		rc = -EIO;
	}

	close(fd);
	return rc;
}


int write_file_with_counter(const char *pattern, const void *buffer,
			int length)
{
	static int counter = 1;
	char filename[1024] = {0};

	sprintf(filename, pattern, counter++);
	return write_file(filename, buffer, length);
}
#endif

void prepare_upiu(struct ufs_bsg_request *bsg_req,
		__u8 query_req_func, __u16 data_len,
		__u8 opcode, __u8 idn, __u8 index, __u8 sel)
{
	bsg_req->msgcode = UPIU_TRANSACTION_QUERY_REQ;

	/* Fill UPIU header */
	bsg_req->upiu_req.header.dword_0 =
		UPIU_HEADER_DWORD(UPIU_TRANSACTION_QUERY_REQ, 0, 0, 0);
	bsg_req->upiu_req.header.dword_1 =
		UPIU_HEADER_DWORD(0, query_req_func, 0, 0);
	bsg_req->upiu_req.header.dword_2 =
		UPIU_HEADER_DWORD(0, 0, data_len >> 8, (__u8)data_len);

	/* Fill Transaction Specific Fields */
	bsg_req->upiu_req.qr.opcode = opcode;
	bsg_req->upiu_req.qr.idn = idn;
	bsg_req->upiu_req.qr.index = index;
	bsg_req->upiu_req.qr.selector = sel;
	bsg_req->upiu_req.qr.length = htobe16(data_len);
}

int send_bsg_sg_io(int fd, struct ufs_bsg_request *request_buff,
		struct ufs_bsg_reply *reply_buff, __u32 req_buf_len,
		__u32 reply_buf_len, __u8 *data_buf)
{
	int ret;
	struct sg_io_v4 io_hdr_v4 = {0};

	io_hdr_v4.guard = 'Q';
	io_hdr_v4.protocol = BSG_PROTOCOL_SCSI;
	io_hdr_v4.subprotocol = BSG_SUB_PROTOCOL_SCSI_TRANSPORT;
	io_hdr_v4.response = (__u64)reply_buff;
	io_hdr_v4.max_response_len = BSG_REPLY_SZ;
	io_hdr_v4.request_len = BSG_REQUEST_SZ;
	io_hdr_v4.request = (__u64)request_buff;

	if (req_buf_len > 0) {
		/* write descriptor */
		io_hdr_v4.dout_xferp = (__u64)(data_buf);
		io_hdr_v4.dout_xfer_len = req_buf_len;
	} else if (reply_buf_len > 0) {
		/* read descriptor */
		io_hdr_v4.din_xferp = (__u64)(data_buf);
		io_hdr_v4.din_xfer_len = reply_buf_len;
	}

	WRITE_LOG("%s cmd = %x req_len %d , res_len %d\n", __func__,
		request_buff->upiu_req.qr.idn, req_buf_len,
		reply_buf_len);
#ifdef DEBUG
	write_file_with_counter("bsg_reg_%d.bin",
				&request_buff->upiu_req,
				sizeof(struct utp_upiu_req));
#endif

	while (((ret = ioctl(fd, SG_IO, &io_hdr_v4)) < 0) &&
		((errno == EINTR) || (errno == EAGAIN)))
		;

	if (io_hdr_v4.info != 0) {
		print_error("Command fail with status %x ",
			io_hdr_v4.info);

		ret = -EINVAL;
	}
#ifdef DEBUG
	write_file_with_counter("bsg_rsp_%d.bin", reply_buff,
			BSG_REPLY_SZ);
#endif
	WRITE_LOG("%s res_len %d\n", __func__,
		reply_buff->reply_payload_rcv_len);
	return ret;
}
