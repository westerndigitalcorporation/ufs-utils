/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2017 Micron Technology Inc.
 *
 * Author:
 *	Bean Huo <beanhuo@micron.com>
 *
 */
#ifndef RPMB_H_
#define RPMB_H_

#define RPMB_MSG_STUFF_BYTES	196
#define RPMB_MSG_KEY_SIZE	32
#define RPMB_MSG_DATA_SIZE	256
#define RPMB_MSG_NONCE_SIZE	16
#define RPMB_MSG_WC_SIZE	4
#define RPMB_MSG_ADDR_SIZE	2
#define RPMB_MSG_BLK_CNT_SIZE	2
#define RPMB_MSG_RESULT_SIZE	2
#define RPMB_MSG_REQ_RESP_SIZE	2
#define RPMB_MSG_SIZE 512
#define RPMB_INPUT_SIZE_FOR_MAC 284 /*Input to the MAC calculation is
				      the concatenation of the fields
				      in the RPMB Message Data Frames
				      from byte 228 to byte 511 (stuff_bytes
				      bytes and the MAC are excluded)
				      */

#define RPMB_KEY_WRITE_REQ	0x0001 /* Program RPMB Authentication Key */
#define RPMB_WC_READ_REQ	0x0002 /* Read RPMB write counter */
#define RPMB_WRITE_REQ		0x0003 /* Write data to RPMB partition */
#define RPMB_READ_REQ		0x0004 /* Read data from RPMB partition */
#define RPMB_RESULT_RD_REQ	0x0005 /* Read result request  (Internal) */
#define RPMB_KEY_PROG_RSP	0x0100 /* Key Prog. Response */
#define RPMB_WC_READ_RSP	0x0200 /* Read Write_Counter value response*/
#define RPMB_WRITE_RSP		0x0300 /* Write response */
#define RPMB_READ_RSP		0x0400 /* Read Response */

/*
 * struct rpmb_mesg__frame - RPMB message data frame
 */
struct rpmb_mesg_frame {
	__u8 stuff_bytes[RPMB_MSG_STUFF_BYTES];
	__u8 key_mac[RPMB_MSG_KEY_SIZE];
	__u8 data[RPMB_MSG_DATA_SIZE];
	__u8 nonce[RPMB_MSG_NONCE_SIZE];
	__u32 write_counter;
	__u16 addr;
	__u16 block_count;
	__u16 result;
	__u16 req_resp;
} __packed;

enum rpmb_type {
	RPMB_STATUS = 1,
	RPMB_DATA_READ,
	RPMB_DATA_WRITE,
	RPMB_PROGRAM_KEY,
	RPMB_READ_COUNTER
};

enum rpmb_op_result {
	NO_ERROR,
	GENERAL_FAILURE,
	AUTH_FAILURE,
	COUNTER_FAILURE,
	ADDR_FAILURE,
	WRITE_FAILURE,
	READ_FAILURE,
	KEY_NOT_PROGRAMMED,
	WT_PROT_CONFIG_FAILURE,
	INVALID_WT_PROT_CONFIG_PARA,
	SEC_WT_PROT_NOT_APPLICABLE
};

struct ufs_rpmb_type {
	const char *name;
	enum rpmb_type type;
};

struct rpmb_opt {
	enum rpmb_type type;
	char bsg_path[1024];
	char key_path[1024];
	char io_file[1024];
	__u16 block_counts;
	__u16 addr;
};

void rpmb_help(char *tool_name);
int do_rpmb(struct tool_options *opt);
#endif /*RPMB_H_*/
