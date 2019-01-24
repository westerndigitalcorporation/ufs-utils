// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2018 Western Digital Corporation

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
	int file;
	int rc = OK;
	int ret;

	WRITE_LOG("writing binary %s length=%d\n", name, length);
	file = open(name, O_RDWR | O_CREAT | O_TRUNC |
			O_SYNC, S_IWUSR | S_IRUSR);
	if (file == -1) {
		WRITE_LOG("%s: failed in open rc=%d errno=%d", __func__, rc,
			errno);
		return INVALID;
	}
	ret = write(file, buffer, length);
	if (length !=  ret) {
		WRITE_LOG("%s: failed in write rc=%d errno=%d", __func__, rc,
			errno);
		rc = INVALID;
	}
	close(file);
	return rc;
}


static int write_file_with_counter(const char *pattern, const void *buffer,
	int length)
{
	int rc;
	static int counter = 1;
	char filename[1024] = {0};

	sprintf(filename, pattern, counter++);
	rc = write_file(filename, buffer, length);
	return rc;
}
#endif

void prepare_upiu(struct ufs_bsg_request *bsg_req,
		__u8 query_req_func, __u16 data_len,
		__u8 opcode, __u8 idn, __u8 index)
{
	bsg_req->msgcode = UPIU_TRANSACTION_QUERY_REQ;

	/* Fill UPIU header */
	bsg_req->upiu_req.header.dword_0 = UPIU_HEADER_DWORD(
			UPIU_TRANSACTION_QUERY_REQ, 0, 0, 0);
	bsg_req->upiu_req.header.dword_1 = UPIU_HEADER_DWORD(0, query_req_func,
		0, 0);
	bsg_req->upiu_req.header.dword_2 = UPIU_HEADER_DWORD(0, 0,
		data_len >> 8, (__u8)data_len);

	/* Fill Transaction Specific Fields */
	bsg_req->upiu_req.qr.opcode = opcode;
	bsg_req->upiu_req.qr.idn = idn;
	bsg_req->upiu_req.qr.index = index;
	bsg_req->upiu_req.qr.length = htobe16(data_len);
}

int send_bsg_sg_io(int fd,
	struct ufs_bsg_request *request_buff,
	struct ufs_bsg_reply *reply_buff,
	__u32 request_len,
	__u32 reply_len)
{
	int ret;
	struct sg_io_v4 io_hdr_v4 = {0};

	io_hdr_v4.guard = 'Q';
	io_hdr_v4.protocol = BSG_PROTOCOL_SCSI;
	io_hdr_v4.subprotocol = BSG_SUB_PROTOCOL_SCSI_TRANSPORT;
	io_hdr_v4.response = (__u64)reply_buff;
	io_hdr_v4.max_response_len = reply_len;
	io_hdr_v4.request_len = request_len;
	io_hdr_v4.request = (__u64)request_buff;

	WRITE_LOG("Start : %s cmd = %x req_len %d , res_len %d\n",
		__func__, request_buff->upiu_req.qr.idn,
		request_len, reply_len);
#ifdef DEBUG
	ret = write_file_with_counter("bsg_reg_%d.bin",
		(void *)&(request_buff->upiu_req),
		(int)(sizeof(struct utp_upiu_req)));
	if (ret == INVALID)
		return ERROR;
#endif

	while (((ret = ioctl(fd, SG_IO, &io_hdr_v4)) < 0) &&
		((errno == EINTR) || (errno == EAGAIN)))
		;

	if (io_hdr_v4.info != 0) {
		print_error("Command fail with status %x ",
			io_hdr_v4.info);

		ret = INVALID;
	}
#ifdef DEBUG
	ret = write_file_with_counter("bsg_rsp_%d.bin",
			(void *)&(reply_buff->upiu_rsp),
			(int)(sizeof(struct utp_upiu_req)));
#endif
	return ret;
}
