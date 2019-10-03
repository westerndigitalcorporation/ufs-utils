/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Copyright (C) 2019 Western Digital Corporation or its affiliates */

#ifndef BSG_UTIL_H_
#define BSG_UTIL_H_

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

#define SENSE_BUFF_LEN	(32)
#define WRITE_BUF_CMDLEN 10
#define READ_BUF_CMDLEN 10
#define WRITE_BUFFER_CMD 0x3B
#define READ_BUFFER_CMD 0x3c

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
	__u32 result;

	/* If there was reply_payload, how much was received? */
	__u32 reply_payload_rcv_len;

	struct utp_upiu_req upiu_rsp;
};
#endif /* SCSI_BSG_UFS_H.*/


#define BSG_REPLY_SZ (sizeof(struct ufs_bsg_reply))
#define BSG_REQUEST_SZ (sizeof(struct ufs_bsg_request))

int send_bsg_scsi_trs(int fd, struct ufs_bsg_request *request_buff,
		struct ufs_bsg_reply *reply_buff, __u32 request_len,
		__u32 reply_len, __u8 *data_buf);
void prepare_upiu(struct ufs_bsg_request *bsg_req, __u8 query_req_func,
		__u16 data_len, __u8 opcode, __u8 idn, __u8 index, __u8 sel);
int read_buffer(int fd, __u8 *buf, uint8_t mode, __u8 buf_id,
		__u32 buf_offset, int byte_count);
int write_buffer(int fd, __u8 *buf, __u8 mode, __u8 buf_id, __u32 buf_offset,
		int byte_count);
#endif /* BSG_UTIL_H_ */

