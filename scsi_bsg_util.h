/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Copyright (C) 2019 Western Digital Corporation or its affiliates */

#ifndef BSG_UTIL_H_
#define BSG_UTIL_H_

#include <stdbool.h>

/* In case include/uapi/scsi/scsi_bsg_ufs.h is not included*/
#ifndef SCSI_BSG_UFS_H
/*
 * This file intended to be included by both kernel and user space
 */

#define UFS_CDB_SIZE	16

#define BUFFER_VENDOR_MODE 0x01
#define BUFFER_DATA_MODE 0x02
#define BUFFER_FFU_MODE 0x0E
#define BUFFER_EHS_MODE 0x1C

#define SG_DXFER_NONE -1        /* e.g. a SCSI Test Unit Ready command */
#define SG_DXFER_TO_DEV -2      /* e.g. a SCSI WRITE command */
#define SG_DXFER_FROM_DEV -3    /* e.g. a SCSI READ command */

#define SENSE_BUFF_LEN	(18)
#define WRITE_BUF_CMDLEN 10
#define READ_BUF_CMDLEN 10
#define SEC_PROTOCOL_TIMEOUT_MSEC	(1000)
#define SEC_PROTOCOL_CMD_SIZE		(12)
#define SEC_PROTOCOL_UFS		(0xEC)
#define SEC_SPECIFIC_UFS_RPMB		(0x0001)
#define WRITE_BUFFER_CMD 0x3B
#define READ_BUFFER_CMD 0x3c
#define SECURITY_PROTOCOL_IN  0xa2
#define SECURITY_PROTOCOL_OUT 0xb5

/**
 * struct utp_upiu_header - UPIU header structure
 * @dword_0: UPIU header DW-0
 * @dword_1: UPIU header DW-1
 * @dword_2: UPIU header DW-2
 */
struct utp_upiu_header {
	__be32 dword_0;
	__be32 dword_1;
	__be32 dword_2;
};

/**
 * struct utp_upiu_query - upiu request buffer structure for
 * query request.
 * @opcode: command to perform B-0
 * @idn: a value that indicates the particular type of data B-1
 * @index: Index to further identify data B-2
 * @selector: Index to further identify data B-3
 * @reserved_osf: spec reserved field B-4,5
 * @length: number of descriptor bytes to read/write B-6,7
 * @value: Attribute value to be written DW-5
 * @reserved: spec reserved DW-6,7
 */
struct utp_upiu_query {
	__u8 opcode;
	__u8 idn;
	__u8 index;
	__u8 selector;
	__be16 reserved_osf;
	__be16 length;
	__be32 value;
	__be32 reserved[2];
};

/**
 * struct utp_upiu_cmd - Command UPIU structure
 * @data_transfer_len: Data Transfer Length DW-3
 * @cdb: Command Descriptor Block CDB DW-4 to DW-7
 */
struct utp_upiu_cmd {
	__be32 exp_data_transfer_len;
	__u8 cdb[UFS_CDB_SIZE];
};

/**
 * struct utp_upiu_req - general upiu request structure
 * @header:UPIU header structure DW-0 to DW-2
 * @sc: fields structure for scsi command DW-3 to DW-7
 * @qr: fields structure for query request DW-3 to DW-7
 */
struct utp_upiu_req {
	struct utp_upiu_header header;
	union {
		struct utp_upiu_cmd		sc;
		struct utp_upiu_query		qr;
		struct utp_upiu_query		tr;
		/* use utp_upiu_query to host the 4 dwords of uic command */
		struct utp_upiu_query		uc;
	};
};

/* request (CDB) structure of the sg_io_v4 */
struct ufs_bsg_request {
	__u32 msgcode;
	struct utp_upiu_req upiu_req;
};

/* response (request sense data) structure of the sg_io_v4 */
struct ufs_bsg_reply {
	/*
	 * The completion result. Result exists in two forms:
	 * if negative, it is an -Exxx system errno value. There will
	 * be no further reply information supplied.
	 * else, it's the 4-byte scsi error result, with driver, host,
	 * msg and status fields. The per-msgcode reply structure
	 * will contain valid data.
	 */
	int result;

	/* If there was reply_payload, how much was received? */
	__u32 reply_payload_rcv_len;

	struct utp_upiu_req upiu_rsp;
};

struct advanced_rpmb_meta_info {
	__u16 req_resp_type;
	__u8 nonce[16];
	__u32 write_counter;
	__u16 addr;
	__u16 block_count;
	__u16 result;
} __attribute__((__packed__));

struct ufs_ehs {
	 __u8 blenght;
	 __u8 lehs_type;
	 __u16 wehssub_type;
	 union {
	struct advanced_rpmb_meta_info meta;
	char meta_bytes[28];
	 };
	 __u8 mac_key[32];
} __attribute__((__packed__));

struct ufs_rpmb_request {
	struct ufs_bsg_request bsg_request;
	struct ufs_ehs ehs_req;
};

struct ufs_rpmb_reply {
	struct ufs_bsg_reply bsg_reply;
	struct ufs_ehs ehs_rsp;
};

#endif /* SCSI_BSG_UFS_H.*/

struct rpmb_frame {
	__u8  stuff[196];
	__u8  key_mac[32];
	__u8  data[256];
	__u8  nonce[16];
	__u32 write_counter;
	__u16 addr;
	__u16 block_count;
	__u16 result;
	__u16 req_resp;
};

#define BSG_REPLY_SZ (sizeof(struct ufs_bsg_reply))
#define BSG_REQUEST_SZ (sizeof(struct ufs_bsg_request))
int send_bsg_scsi_trs(int fd, void *request_buff, void *reply_buff, __u32 req_buf_len,
		      __u32 reply_buf_len, __u32 data_buf_len, __u8 *data_buf, bool write);
void prepare_upiu(struct ufs_bsg_request *bsg_req, __u8 query_req_func,
		__u16 data_len, __u8 opcode, __u8 idn, __u8 index, __u8 sel);
int read_buffer(int fd, __u8 *buf, uint8_t mode, __u8 buf_id,
		__u32 buf_offset, int byte_count, __u8 sg_type);
int write_buffer(int fd, __u8 *buf, __u8 mode, __u8 buf_id, __u32 buf_offset,
		int byte_count, __u8 sg_type);
int scsi_security_out(int fd, struct rpmb_frame *frame_in,
		unsigned int cnt, __u8 region, __u8 sg_type);
int scsi_security_in(int fd, struct rpmb_frame *frame, int cnt,
		__u8 region, __u8 sg_type);
int prepare_security_cdb(__u8 *cdb, unsigned int data_len, __u8 region, __u8 opcode);
void prepare_command_upiu(struct utp_upiu_req *upiu_req, __u8 flags, __u8 lun, __u8 ehs_len, __u8 *cdb, __u8 cdb_len,
			  __u32 exp_data_transfer_len);
#endif /* BSG_UTIL_H_ */

