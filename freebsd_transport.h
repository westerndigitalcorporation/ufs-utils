/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Copyright (C) 2026 Samsung Electronics Co., Ltd. */
/*
 * FreeBSD replacements for the two transport functions in
 * scsi_bsg_util.c. Those two are the only places ufs-utils talks to the
 * kernel.
 */

#ifndef FREEBSD_TRANSPORT_H_
#define FREEBSD_TRANSPORT_H_

#include <stdbool.h>
#include <linux/types.h>

/* Sends a SCSI CDB. dir is SG_DXFER_TO_DEV, SG_DXFER_FROM_DEV or
   SG_DXFER_NONE. */
int freebsd_send_scsi_cmd(int fd, const __u8 *cdb, void *buf,
		__u8 cmd_len, __u32 byte_cnt, int dir);

/* Sends a raw UPIU. Reads the message type from the request msgcode. */
int freebsd_send_bsg_trs(int fd, void *request_buff, void *reply_buff,
		__u32 req_buf_len, __u32 reply_buf_len,
		__u32 data_buf_len, __u8 *data_buf, bool write);

/* sense_key_string lives in scsi_bsg_util.c. It is static on Linux, so
 * this declares it only for the FreeBSD transport. */
const char *sense_key_string(__u8 key);

#endif /* FREEBSD_TRANSPORT_H_ */
