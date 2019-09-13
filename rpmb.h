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

#ifndef _UAPI_LINUX_LIMITS_H
#define PATH_MAX 4096
#endif

#define RPMB_MSG_STUFF_BYTES	196
#define RPMB_MSG_KEY_SIZE	32
#define RPMB_MSG_DATA_SIZE	256
#define RPMB_MSG_NONCE_SIZE	16
#define RPMB_MSG_SIZE 512
#define RPMB_INPUT_SIZE_FOR_MAC 284 /* Input to the MAC calculation is
				     * the concatenation of the fields
				     * in the RPMB Message Data Frames
				     * from byte 228 to byte 511 (stuff_bytes
				     * bytes and the MAC are excluded)
				     */
/*
 * Request Message Types
 */
#define RPMB_KEY_WRITE_REQ	0x0001 /* Program RPMB Authentication Key */
#define RPMB_WC_READ_REQ	0x0002 /* Read RPMB write counter */
#define RPMB_WRITE_REQ		0x0003 /* Write data to RPMB partition */
#define RPMB_READ_REQ		0x0004 /* Read data from RPMB partition */
#define RPMB_RESULT_RD_REQ	0x0005 /* Read result request  (Internal) */
#define SEC_PROT_CFG_BLK_WRITE	0x0006 /* Protect Configuration Block write */
#define SEC_PROT_CFG_BLK_READ	0x0007 /* Protect Configuration Block read */

/*
 * struct  protect_cfg_blk - Secure Write Protect Configuration Block
 */
struct protect_cfg_blk {
	__u8 lun;
	__u8 data_len;
	__u8 reserved_0[14];
	__u8 entry_0[16];
	__u8 entry_1[16];
	__u8 entry_2[16];
	__u8 entry_3[16];
	__u8 reserved_1[175];
};

/*
 * struct rpmb_mesg__frame - RPMB message
 */
struct rpmb_mesg_frame {
	__u8 stuff_bytes[RPMB_MSG_STUFF_BYTES];
	__u8 key_mac[RPMB_MSG_KEY_SIZE];
	union {
	__u8 data[RPMB_MSG_DATA_SIZE];
	struct protect_cfg_blk cfg_blk;
	};
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
	RPMB_READ_COUNTER,
	RPMB_CFG_BLK_WRITE,
	RPMB_CFG_BLK_READ
};

struct rpmb_opt {
	int type;
	char bsg_path[PATH_MAX];
	char key_path[PATH_MAX];
	char io_file[PATH_MAX];
	int block_counts;
	int addr;
	int region;
	int lun;
};

struct ufs_rpmb_type {
	const char *name;
	int type;
	int (*func)(struct rpmb_opt *opt);
};

void rpmb_help(char *tool_name);
int do_rpmb(struct tool_options *opt);
#endif /*RPMB_H_*/
