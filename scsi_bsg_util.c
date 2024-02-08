// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2019 Western Digital Corporation or its affiliates */

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <stdint.h>
#include <endian.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdbool.h>
#include <string.h>

#include "ioctl.h"
#include "ufs.h"
#include "scsi_bsg_util.h"
#include "ufs_rpmb.h"

#define UPIU_HEADER_DWORD(byte3, byte2, byte1, byte0)\
			htobe32((byte3 << 24) | (byte2 << 16) |\
				(byte1 << 8) | (byte0))
#define SEC_SPEC_OFFSET 2
#define SEC_TRANS_LEN_OFFSET 6
/* description of the sense key values */
static const char *const snstext[] = {
	"No Sense",	    /* 0: There is no sense information */
	"Recovered Error",  /* 1: The last command completed successfully
				  but used error correction */
	"Not Ready",	    /* 2: The addressed target is not ready */
	"Medium Error",	    /* 3: Data error detected on the medium */
	"Hardware Error",   /* 4: Controller or device failure */
	"Illegal Request",  /* 5: Error in request */
	"Unit Attention",   /* 6: Removable medium was changed, or
				  the target has been reset, or ... */
	"Data Protect",	    /* 7: Access to the data is blocked */
	"Blank Check",	    /* 8: Reached unexpected written or unwritten
				  region of the medium */
	"Vendor Specific",
	"Copy Aborted",	    /* A: COPY or COMPARE was aborted */
	"Aborted Command",  /* B: The target aborted the command */
	"Equal",	    /* C: A SEARCH DATA command found data equal */
	"Volume Overflow",  /* D: Medium full with still data to be written */
	"Miscompare",	    /* E: Source data and data on the medium
				  do not agree */
};

static int send_scsi_cmd(int fd, const __u8 *cdb, void *buf,
		__u8 cmd_len, __u32 byte_cnt, int dir, __u8 sg_type);

/* Get sense key string or NULL if not available */
static const char *sense_key_string(__u8 key)
{
	if (key <= 0xE)
		return snstext[key];

	return NULL;
}

static inline void put_unaligned_be24(__u32 val, void *p)
{
	((__u8 *)p)[0] = (val >> 16) & 0xff;
	((__u8 *)p)[1] = (val >> 8) & 0xff;
	((__u8 *)p)[2] = val & 0xff;
}

static int write_file_with_counter(const char *pattern, const void *buffer,
			int length)
{
#ifdef DEBUG
	static int counter = 1;
	char filename[1024] = {0};
	sprintf(filename, pattern, counter++);
	return write_file(filename, buffer, length);
#else
	return 0;
#endif
}

int write_buffer(int fd, __u8 *buf, __u8 mode, __u8 buf_id, __u32 buf_offset,
		int byte_count, __u8 sg_type)
{
	int ret;
	unsigned char write_buf_cmd [WRITE_BUF_CMDLEN] = {
		WRITE_BUFFER_CMD, 0, 0, 0, 0, 0, 0, 0, 0, 0};

	if (fd < 0 || byte_count < 0) {
		perror("scsi write cmd: wrong parameters");
		return -EINVAL;
	}

	write_buf_cmd[1] = mode;
	write_buf_cmd[2] = buf_id;
	put_unaligned_be24((uint32_t)buf_offset, write_buf_cmd + 3);
	put_unaligned_be24(byte_count, write_buf_cmd + 6);
	WRITE_LOG("Start : %s mode %d , buf_id %d", __func__, mode, buf_id);
	ret = send_scsi_cmd(fd, write_buf_cmd, buf,
			WRITE_BUF_CMDLEN, byte_count,
			SG_DXFER_TO_DEV, sg_type);
	if (ret < 0) {
		print_error("SG_IO WRITE BUFFER data error ret %d", ret);
	}
	return ret;
}

int read_buffer(int fd, __u8 *buf, __u8 mode, __u8 buf_id,
	__u32 buf_offset, int byte_count, __u8 sg_type)
{

	int ret;
	unsigned char read_buf_cmd[READ_BUF_CMDLEN] = {READ_BUFFER_CMD,
		0, 0, 0, 0, 0, 0, 0, 0, 0};

	if (fd < 0 || byte_count < 0) {
		print_error("scsi read cmd: wrong parameters");
		return -EINVAL;
	}

	read_buf_cmd[1] = mode;
	read_buf_cmd[2] = buf_id;
	put_unaligned_be24((__u32)buf_offset, read_buf_cmd + 3);
	put_unaligned_be24((__u32)byte_count, read_buf_cmd + 6);
	WRITE_LOG("Start : %s\n", __func__);
	ret = send_scsi_cmd(fd, read_buf_cmd, buf,
			READ_BUF_CMDLEN, byte_count,
			SG_DXFER_FROM_DEV, sg_type);

	if (ret < 0) {
		print_error("SG_IO READ BUFFER data error ret %d", ret);
	}

	return ret;
}

int scsi_security_in(int fd, struct rpmb_frame *frame, int cnt, __u8 region,
		__u8 sg_type)
{
	int ret;
	__u32 trans_len = cnt * sizeof(struct rpmb_frame);
	__u16 sec_spec = (region << 8) | SEC_SPECIFIC_UFS_RPMB;
	unsigned char sec_in_cmd[SEC_PROTOCOL_CMD_SIZE] = {
			SECURITY_PROTOCOL_IN, SEC_PROTOCOL_UFS,
			0, 0, 0, 0, 0, 0, 0, 0, 0, 0};

	WRITE_LOG("Start : %s\n", __func__);
	if (fd < 0 || frame == NULL || cnt <= 0) {
		print_error("scsi sec_in cmd: wrong parameters");
		return ERROR;
	}

	*(__u16 *)(sec_in_cmd + SEC_SPEC_OFFSET) = htobe16(sec_spec);
	*(__u32 *)(sec_in_cmd + SEC_TRANS_LEN_OFFSET) = htobe32(trans_len);

	ret = send_scsi_cmd(fd, sec_in_cmd, frame, SEC_PROTOCOL_CMD_SIZE,
		trans_len, SG_DXFER_FROM_DEV, sg_type);

	return ret;
}

int scsi_security_out(int fd, struct rpmb_frame *frame_in,
		unsigned int cnt, __u8 region, __u8 sg_type)
{
	int ret;
	__u32 trans_len = cnt * sizeof(struct rpmb_frame);
	__u16 sec_spec = (region << 8) | SEC_SPECIFIC_UFS_RPMB;
	unsigned char sec_out_cmd[SEC_PROTOCOL_CMD_SIZE] = {
			SECURITY_PROTOCOL_OUT, SEC_PROTOCOL_UFS,
			0, 0, 0, 0, 0, 0, 0, 0, 0, 0};

	if (fd < 0 || frame_in == NULL || cnt <= 0) {
		print_error("scsi sec_out cmd: wrong parameters");
		return ERROR;
	}
	*(__u16 *)(sec_out_cmd + SEC_SPEC_OFFSET) = htobe16(sec_spec);
	*(__u32 *)(sec_out_cmd + SEC_TRANS_LEN_OFFSET) = htobe32(trans_len);
	ret = send_scsi_cmd(fd, sec_out_cmd, frame_in,
			SEC_PROTOCOL_CMD_SIZE, trans_len,
			SG_DXFER_TO_DEV, sg_type);

	return ret;
}

int prepare_security_cdb(__u8 *cdb, unsigned int data_len, __u8 region, __u8 opcode)
{

	if (cdb == NULL)
		return ERROR;

	__u16 sec_spec = (region << 8) | SEC_SPECIFIC_UFS_RPMB;

	cdb[0] = opcode;
	cdb[1] = SEC_PROTOCOL_UFS;

	*(__u16 *)(cdb + SEC_SPEC_OFFSET) = htobe16(sec_spec);
	*(__u32 *)(cdb + SEC_TRANS_LEN_OFFSET) = htobe32(data_len);

	return 0;
}

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


void prepare_command_upiu(struct utp_upiu_req *upiu_req, __u8 flags, __u8 lun, __u8 ehs_len,
			  __u8 *cdb, __u8 cdb_len, __u32 exp_data_transfer_len)
{

	/* Fill UPIU header */
	upiu_req->header.dword_0 = UPIU_HEADER_DWORD(UPIU_TRANSACTION_COMMAND, flags, lun, 0);
	upiu_req->header.dword_1 = UPIU_HEADER_DWORD(0, 0, 0, 0);
	upiu_req->header.dword_2 = UPIU_HEADER_DWORD(ehs_len, 0, 0, 0);

	/* Fill Transaction Specific Fields */
	upiu_req->sc.exp_data_transfer_len = htobe32(exp_data_transfer_len);
	memcpy(upiu_req->sc.cdb, cdb, cdb_len);
}

/**
 * send_scsi_cmd - Utility function for SCSI command sending
 * @fd: bsg driver file descriptor
 * @cdb: pointer to SCSI cmd cdb buffer
 * @buf: pointer to the SCSI cmd data buffer
 * @cmd_len: SCSI command length
 * @byte_cnt: SCSI data length
 * @dir: The cmd direction
 *
 **/
static int send_scsi_cmd(int fd, const __u8 *cdb, void *buf, __u8 cmd_len,
		__u32 byte_cnt, int dir, __u8 sg_type)
{
	int ret;
	void *sg_struct;
	struct sg_io_v4 io_hdr_v4 = { 0 };
	struct sg_io_hdr io_hdr_v3 = { 0 };
	__u8 sense_buffer[SENSE_BUFF_LEN] = { 0 };

	if ((byte_cnt && buf == NULL) || cdb == NULL) {
		print_error("send_scsi_cmd: wrong parameters");
		return -EINVAL;
	}

	if (sg_type == SG4_TYPE) {
		io_hdr_v4.guard = 'Q';
		io_hdr_v4.protocol = BSG_PROTOCOL_SCSI;
		io_hdr_v4.subprotocol = BSG_SUB_PROTOCOL_SCSI_CMD;
		io_hdr_v4.response = (__u64)sense_buffer;
		io_hdr_v4.max_response_len = SENSE_BUFF_LEN;
		io_hdr_v4.request_len = cmd_len;
		if (dir == SG_DXFER_FROM_DEV) {
			io_hdr_v4.din_xfer_len = (__u32)byte_cnt;
			io_hdr_v4.din_xferp = (__u64)buf;
		} else {
			io_hdr_v4.dout_xfer_len = (__u32)byte_cnt;
			io_hdr_v4.dout_xferp = (__u64)buf;
		}
			io_hdr_v4.request = (__u64)cdb;
		sg_struct = &io_hdr_v4;
	}
	else {
		io_hdr_v3.interface_id = 'S';
		io_hdr_v3.cmd_len = cmd_len;
		io_hdr_v3.mx_sb_len = SENSE_BUFF_LEN;
		io_hdr_v3.dxfer_direction = dir;
		io_hdr_v3.dxfer_len = byte_cnt;
		io_hdr_v3.dxferp = buf;
		/* pointer to command buf (rbufCmdBlk) */
		io_hdr_v3.cmdp = (unsigned char *)cdb;
		io_hdr_v3.sbp = sense_buffer;
		io_hdr_v3.timeout = DEF_TIMEOUT_MSEC;
		sg_struct = &io_hdr_v3;
	}
	WRITE_LOG("Start : %s cmd = %x len %d sg_type %d\n", __func__, cdb[0],
			byte_cnt, sg_type);

	write_file_with_counter("scsi_cmd_cdb_%d.bin",
			cdb, cmd_len);

	while (((ret = ioctl(fd, SG_IO, sg_struct)) < 0) &&
		((errno == EINTR) || (errno == EAGAIN)));
	if (sg_type == SG4_TYPE) {
		if (io_hdr_v4.info != 0) {
			print_error("Command fail with status %x , senseKey %s, asc 0x%02x, ascq 0x%02x",
				    io_hdr_v4.info,
				    sense_key_string(sense_buffer[2]),
				    sense_buffer[12],
				    sense_buffer[13]);
			ret = -EINVAL;
		}
	}
	else {
		if (io_hdr_v3.status) {
			print_error("Command fail with status %x , senseKey %s, asc 0x%02x, ascq 0x%02x",
				    io_hdr_v3.status,
				    sense_key_string(sense_buffer[2]),
				    sense_buffer[12],
				    sense_buffer[13]);
			ret = -EINVAL;
		}

	}

	return ret;
}

/**
 * send_bsg_scsi_trs - Utility function for SCSI transport cmd sending
 * @fd: ufs bsg driver file descriptor
 * @request_buff: pointer to the Query Request
 * @reply_buff: pointer to the Query Response
 * @req_buf_len: Query Request data length
 * @reply_buf_len: Query Response data length
 * @data_buf: pointer to the data buffer
 * @write: If data_buff is not NULL, it indicates that this is a data write request or data read
 *
 * The function using ufs bsg infrastructure in linux kernel (/dev/ufs-bsg)
 * in order to send Query request command
 **/
int send_bsg_scsi_trs(int fd, void *request_buff, void *reply_buff, __u32 req_buf_len,
			__u32 reply_buf_len, __u32 data_buf_len, __u8 *data_buf, bool write)
{
	int ret;
	struct sg_io_v4 io_hdr_v4 = { 0 };

	if (request_buff == NULL || reply_buff == NULL) {
		print_error("%s: wrong parameters", __func__);
		return -EINVAL;
	}

	if (data_buf_len) {
		if (data_buf == NULL) {
			print_error("%s: data_buf is NULL", __func__);
			return -EINVAL;
		}
	}

	io_hdr_v4.guard = 'Q';
	io_hdr_v4.protocol = BSG_PROTOCOL_SCSI;
	io_hdr_v4.subprotocol = BSG_SUB_PROTOCOL_SCSI_TRANSPORT;
	io_hdr_v4.response = (__u64)reply_buff;
	io_hdr_v4.max_response_len = reply_buf_len;
	io_hdr_v4.request_len = req_buf_len;
	io_hdr_v4.request = (__u64)request_buff;

	if (data_buf) {
		if (write) {
			/* write descriptor */
			io_hdr_v4.dout_xferp = (__u64)(data_buf);
			io_hdr_v4.dout_xfer_len = data_buf_len;
		} else  {
			/* read descriptor */
			io_hdr_v4.din_xferp = (__u64)(data_buf);
			io_hdr_v4.din_xfer_len = data_buf_len;
		}
	}

	WRITE_LOG("%s cmd = %x req_len %d, res_len %d\n", __func__,
		((struct ufs_bsg_request *)request_buff)->upiu_req.qr.idn, req_buf_len,
		reply_buf_len);

	write_file_with_counter("bsg_reg_%d.bin",
				&((struct ufs_bsg_request *)request_buff)->upiu_req,
				sizeof(struct utp_upiu_req));


	while (((ret = ioctl(fd, SG_IO, &io_hdr_v4)) < 0) &&
		((errno == EINTR) || (errno == EAGAIN)))
		;

	if (io_hdr_v4.info != 0) {
		print_error("Command fail with status %x ",
			io_hdr_v4.info);

		ret = -EINVAL;
	}

	write_file_with_counter("bsg_rsp_%d.bin", reply_buff,
			BSG_REPLY_SZ);

	WRITE_LOG("%s res_len %d\n", __func__,
		reply_buff->reply_payload_rcv_len);
	return ret;
}
