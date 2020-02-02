/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Copyright (C) 2019 Western Digital Corporation or its affiliates */

#ifndef UAPI_SCSI_IOCTL_H_
#define UAPI_SCSI_IOCTL_H_

#ifndef SG_IO
/* synchronous SCSI command ioctl, (only in version 3 interface) */
#define SG_IO 0x2285   /* similar effect as write() followed by read() */
#endif

#ifndef _UAPIBSG_H
#include <linux/types.h>

#define DEF_TIMEOUT_MSEC	(60000)
#define BSG_PROTOCOL_SCSI	0

#define BSG_SUB_PROTOCOL_SCSI_CMD	0
#define BSG_SUB_PROTOCOL_SCSI_TMF	1
#define BSG_SUB_PROTOCOL_SCSI_TRANSPORT	2

/*
 * For flag constants below:
 * sg.h sg_io_hdr also has bits defined for it's flags member. These
 * two flag values (0x10 and 0x20) have the same meaning in sg.h . For
 * bsg the BSG_FLAG_Q_AT_HEAD flag is ignored since it is the deafult.
 */
#define BSG_FLAG_Q_AT_TAIL 0x10 /* default is Q_AT_HEAD */
#define BSG_FLAG_Q_AT_HEAD 0x20

struct sg_io_v4 {
	__s32 guard;		/* [i] 'Q' to differentiate from v3 */
	__u32 protocol;		/* [i] 0 -> SCSI , .... */
	__u32 subprotocol;	/* [i] 0 -> SCSI command, 1 -> SCSI task
				   management function, .... */

	__u32 request_len;	/* [i] in bytes */
	__u64 request;		/* [i], [*i] {SCSI: cdb} */
	__u64 request_tag;	/* [i] {SCSI: task tag (only if flagged)} */
	__u32 request_attr;	/* [i] {SCSI: task attribute} */
	__u32 request_priority;	/* [i] {SCSI: task priority} */
	__u32 request_extra;	/* [i] {spare, for padding} */
	__u32 max_response_len;	/* [i] in bytes */
	__u64 response;		/* [i], [*o] {SCSI: (auto)sense data} */

	/* "dout_": data out (to device); "din_": data in (from device) */
	__u32 dout_iovec_count;	/* [i] 0 -> "flat" dout transfer else
				   dout_xfer points to array of iovec */
	__u32 dout_xfer_len;	/* [i] bytes to be transferred to device */
	__u32 din_iovec_count;	/* [i] 0 -> "flat" din transfer */
	__u32 din_xfer_len;	/* [i] bytes to be transferred from device */
	__u64 dout_xferp;	/* [i], [*i] */
	__u64 din_xferp;	/* [i], [*o] */

	__u32 timeout;		/* [i] units: millisecond */
	__u32 flags;		/* [i] bit mask */
	__u64 usr_ptr;		/* [i->o] unused internally */
	__u32 spare_in;		/* [i] */

	__u32 driver_status;	/* [o] 0 -> ok */
	__u32 transport_status;	/* [o] 0 -> ok */
	__u32 device_status;	/* [o] {SCSI: command completion status} */
	__u32 retry_delay;	/* [o] {SCSI: status auxiliary information} */
	__u32 info;		/* [o] additional information */
	__u32 duration;		/* [o] time to complete, in milliseconds */
	__u32 response_len;	/* [o] bytes of response actually written */
	__s32 din_resid;	/* [o] din_xfer_len - actual_din_xfer_len */
	__s32 dout_resid;	/* [o] dout_xfer_len - actual_dout_xfer_len */
	__u64 generated_tag;	/* [o] {SCSI: transport generated task tag} */
	__u32 spare_out;	/* [o] */

	__u32 padding;
};

/*
 * SCSI Generic v3 struct copied from include/scsi/sg.h
 */
typedef struct sg_io_hdr {
	int interface_id;           /* [i] 'S' for SCSI generic (required) */
	int dxfer_direction;        /* [i] data transfer direction  */
	unsigned char cmd_len;      /* [i] SCSI command length ( <= 16 bytes) */
	unsigned char mx_sb_len;    /* [i] max length to write to sbp */
	unsigned short int iovec_count; /* [i] 0 implies no scatter gather */
	unsigned int dxfer_len;     /* [i] byte count of data transfer */
	void *dxferp;              /* [i], [*io] points to data transfer memory
				 or scatter gather list */
	unsigned char *cmdp;       /* [i], [*i] points to command to perform */
	unsigned char *sbp;        /* [i], [*o] points to sense_buffer memory */
	unsigned int timeout;       /* [i] MAX_UINT->no timeout (unit: millisec) */
	unsigned int flags;         /* [i] 0 -> default, see SG_FLAG... */
	int pack_id;                /* [i->o] unused internally (normally) */
	void *usr_ptr;             /* [i->o] unused internally */
	unsigned char status;       /* [o] scsi status */
	unsigned char masked_status;/* [o] shifted, masked scsi status */
	unsigned char msg_status;   /* [o] messaging level data (optional) */
	unsigned char sb_len_wr;    /* [o] byte count actually written to sbp */
	unsigned short int host_status; /* [o] errors from host adapter */
	unsigned short int driver_status;/* [o] errors from software driver */
	int resid;                  /* [o] dxfer_len - actual_transferred */
	unsigned int duration;      /* [o] time taken by cmd (unit: millisec) */
	unsigned int info;          /* [o] auxiliary information */
} sg_io_hdr_t;

#endif /* _UAPIBSG_H */
#endif /* UAPI_SCSI_IOCTL_H_ */
