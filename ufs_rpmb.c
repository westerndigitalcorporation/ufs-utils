// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2019 Western Digital Corporation or its affiliates */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <dirent.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdint.h>
#include <errno.h>
#include <time.h>
#include <stdbool.h>

#include "ufs.h"
#include "ufs_cmds.h"
#include "options.h"
#include "ufs_rpmb.h"
#include "ioctl.h"
#include "hmac_sha2.h"
#include "scsi_bsg_util.h"

enum rpmb_op_type {
	RPMB_WRITE_KEY      = 0x01,
	RPMB_READ_CNT       = 0x02,
	RPMB_WRITE          = 0x03,
	RPMB_READ           = 0x04,
	RPMB_READ_RESP      = 0x05,
	RPMB_SEC_CONF_WRITE = 0x06,
	RPMB_SEC_CONF_READ  = 0x07,

};

/* description of the sense key values */
static const char *const rpmb_res_txt[] = {
	"Success",
	"General failure",
	"Authentication failure",
	"Counter failure",
	"Address failure",
	"Write failure",
	"Read failure",
	"Authentication Key not yet programmed",
	"Secure Write Protect Configuration Block access failure",
	"Invalid Secure Write Protect Block Configuration parameter",
	"Secure Write Protection not applicable"
};

#define RESP_KEY_PROG          0x100
#define RESP_COUNTER_READ      0x200
#define RESP_DATA_WRITE        0x300
#define RESP_DATA_READ         0x400
#define RESP_CONF_BLOCK_WRITE  0x600
#define RESP_CONF_BLOCK_READ   0x700

#define RPMB_KEY_SIZE 32
#define RPMB_MAC_SIZE 32
#define RPMB_NONCE_SIZE 16
#define RPMB_DATA_SIZE 256

#define UFS_BSG_PATH "/dev/ufs-bsg"

#define DEFAULT_RPMB_NUM_BLOCKS 64

#define MAX_ADDRESS 0xFFFF
#define SECOND_BYTE_MASK 0xFF00

#define MAX_RETRY 3

static unsigned char key[RPMB_KEY_SIZE];

#define CUC(x) ((const unsigned char *)(x))

extern int do_read_desc(int fd, struct ufs_bsg_request *bsg_req,
		struct ufs_bsg_reply *bsg_rsp, __u8 idn, __u8 index,
		__u16 desc_buf_len, __u8 *data_buf);

static void hmac_update_frm(hmac_sha256_ctx *ctx, struct rpmb_frame *frm)
{
	hmac_sha256_update(ctx, CUC(frm->data), 256);
	hmac_sha256_update(ctx, CUC(frm->nonce), 16);
	hmac_sha256_update(ctx, CUC(&frm->write_counter), 4);
	hmac_sha256_update(ctx, CUC(&frm->addr), 2);
	hmac_sha256_update(ctx, CUC(&frm->block_count), 2);
	hmac_sha256_update(ctx, CUC(&frm->result), 2);
	hmac_sha256_update(ctx, CUC(&frm->req_resp), 2);
}

static int rpmb_calc_hmac_sha256(struct rpmb_frame *frames, ssize_t blocks_cnt,
		const unsigned char key[], __u32 key_size,
		unsigned char mac[], __u32 mac_size)
{
	hmac_sha256_ctx ctx;
	__u32 i;

	hmac_sha256_init(&ctx, key, key_size);

	for (i = 0; i < blocks_cnt; i++)
		hmac_update_frm(&ctx, (frames + i));

	hmac_sha256_final(&ctx, mac, mac_size);

	return 0;
}

static void print_operation_error(__u16 result)
{
	if (result <= 0xA)
		printf("\n %s\n", rpmb_res_txt[result]);
	else
		printf("\n Unsupported RPMB Operation Error %x\n", result);
}

static int do_rpmb_op(int fd, struct rpmb_frame *frame_in, __u32 in_cnt,
		struct rpmb_frame *frame_out, __u32 out_cnt, __u8 region)
{
	int ret = -EINVAL;
	int try_again;
	__u16 req_resp = 0;

	if (!frame_in || !frame_out || !in_cnt || !out_cnt) {
		print_error("Wrong rpmb parameters");
		goto out;
	}
	for (try_again = 0; try_again < MAX_RETRY; try_again++) {
		ret = scsi_security_out(fd, frame_in, in_cnt, region);
		if (!ret)
			break;
		if (try_again < MAX_RETRY - 1)
			WRITE_LOG("SO failed: %d\n", try_again);
		else
			print_error("SO 1st RPMB cmd failed");
	}

	req_resp = be16toh(frame_in->req_resp & SECOND_BYTE_MASK);
	if ((req_resp == RPMB_WRITE) ||
	    (req_resp == RPMB_WRITE_KEY) ||
	    (req_resp == RPMB_SEC_CONF_WRITE)) {
		memset(&frame_in[0], 0, sizeof(frame_in[0]));
		req_resp = (req_resp & SECOND_BYTE_MASK) | RPMB_READ_RESP;
		frame_in[0].req_resp = htobe16(req_resp);
		for (try_again = 0; try_again < MAX_RETRY; try_again++) {
			ret = scsi_security_out(fd,  &frame_in[0], 1, region);
			if (!ret)
				break;
			if (try_again < MAX_RETRY - 1)
				WRITE_LOG("SO 2 failed: %d\n", try_again);
			else
				print_error("SO 2nd RPMB cmd failed");
		}
	}
	for (try_again = 0; try_again < MAX_RETRY; try_again++) {
		ret = scsi_security_in(fd, frame_out, out_cnt, region);
		if (!ret) {
			WRITE_LOG("Result Response addr %d , write count %d\n",
				  be16toh(frame_out->addr),
				  be32toh(frame_out->write_counter));
			break;
		}
		if (try_again < MAX_RETRY - 1)
			WRITE_LOG("SI failed: %d\n", try_again);
		else
			print_error("SI RPMB cmd failed");
	}
out:
	return ret;
}

static int do_key(int fd, const unsigned char *key, __u8 region)
{
	int ret = INVALID;
	struct rpmb_frame frame_in = { 0 };
	struct rpmb_frame frame_out = { 0 };

	frame_in.req_resp = htobe16(RPMB_WRITE_KEY);

	if (key == NULL) {
		WRITE_LOG0("key is NULL");
		goto out;
	}
	memcpy(frame_in.key_mac, key, sizeof(frame_in.key_mac));
	WRITE_LOG("Start : %s\n", __func__);
	ret = do_rpmb_op(fd, &frame_in, 1, &frame_out, 1, region);

	if (!ret) {
		if (frame_out.result != 0) {
			print_operation_error(be16toh(frame_out.result));
			goto out;
		} else
			printf("RPMB key is programmed\n");
	}
out:
	return ret;
}

static int do_read_counter(int fd, __u32 *cnt, __u8 region,
		bool prn_cnt)
{
	int ret;
	struct rpmb_frame frame_in = { 0 };
	struct rpmb_frame frame_out = { 0 };

	WRITE_LOG("Start : %s %d\n", __func__, region);
	frame_in.req_resp = htobe16(RPMB_READ_CNT);
	ret = do_rpmb_op(fd, &frame_in, 1, &frame_out, 1, region);

	if (!ret) {
		if (frame_out.result != 0) {
			print_operation_error(be16toh(frame_out.result));
		} else {
			if (prn_cnt)
				printf("RPMB write counter = %u\n",
					be32toh(frame_out.write_counter));
			*cnt = be32toh(frame_out.write_counter);
		}
	}
	return ret;
}

static int do_read_rpmb(int fd, int out_fd, unsigned char *key,
	__u16 start_addr, __u16 num_blocks, __u8 region)
{
	int ret = ERROR;
	int i;
	ssize_t write_size;
	__u8 max_num_blocks;
	__u8 num_read_blocks = 0;
	struct rpmb_frame frame_in = { 0 };
	struct rpmb_frame *frames_out = NULL;
	struct rpmb_frame *last_frame;
	struct ufs_bsg_request bsg_req = { 0 };
	struct ufs_bsg_reply bsg_rsp = { 0 };
	int ufs_bsg_fd = INVALID;
	__u8 data_buf[QUERY_DESC_GEOMETRY_MAX_SIZE] = { 0 };

	WRITE_LOG("Start : %s , address %d , num_blocks %d\n", __func__,
		  start_addr, num_blocks);

	ufs_bsg_fd = open(UFS_BSG_PATH, O_RDWR);
	if (ufs_bsg_fd != INVALID) {
		ret = do_read_desc(ufs_bsg_fd, &bsg_req, &bsg_rsp,
				   QUERY_DESC_IDN_GEOMETRY, 0,
				   QUERY_DESC_GEOMETRY_MAX_SIZE, data_buf);
	}

	if (ret) {
		/*
		 * Could not read geometry descriptor, max block set
		 * DEFAULT_RPMB_NUM_BLOCKS);
		 */
		printf("Warning: Cannot get bRPMB_ReadWriteSize");
		max_num_blocks = DEFAULT_RPMB_NUM_BLOCKS;
	} else {
		max_num_blocks = data_buf[0x17];
		WRITE_LOG("max_num_blocks : %d\n", max_num_blocks);
	}

	if (num_blocks > max_num_blocks)
		num_read_blocks = max_num_blocks;
	else
		num_read_blocks = num_blocks;
	while (num_blocks > 0) {
		if (start_addr > MAX_ADDRESS) {
			print_error("Max available address is reached");
			goto out;
		}

		frames_out = (struct rpmb_frame *)calloc(num_read_blocks,
			      sizeof(struct rpmb_frame));
		if (!frames_out) {
			print_error("Cannot allocate %d RPMB frames",
					num_blocks);
			goto out;
		}
		frame_in.req_resp = htobe16(RPMB_READ);
		frame_in.addr = htobe16(start_addr);
		frame_in.block_count = htobe16(num_read_blocks);
		ret = do_rpmb_op(fd, &frame_in, 1, frames_out,
				num_read_blocks, region);

		if (ret != 0) {
			print_error("RPMB operation is failed in addr %d ",
				    start_addr);
			goto out;
		}
		if (frames_out[0].result != 0) {
			print_operation_error(be16toh(frames_out[0].result));
			ret = -EINVAL;
			goto out;
		}
		last_frame = &frames_out[num_read_blocks - 1];
		/* In case an user get the key ,verify the hash */
		if (key != NULL) {
			__u8 mac[RPMB_MAC_SIZE];

			rpmb_calc_hmac_sha256(frames_out, num_read_blocks,
					      key, RPMB_KEY_SIZE,
					      mac, RPMB_MAC_SIZE);
			/*
			 * Compare calculated MAC and MAC from last frame
			 * Note the mac much only in case we read 1 block ,
			 * otherwise the mac field is not much, in all frame ,
			 * include the last one
			 */
			if (memcmp(mac, last_frame->key_mac, sizeof(mac)))
				printf("\nWarning: RPMB MAC mismatch mac\n");
		}
		for (i = 0; i < num_read_blocks; i++) {
			write_size = write(out_fd, &(frames_out[i].data),
					   RPMB_DATA_SIZE);
			if (write_size  !=  RPMB_DATA_SIZE) {
				WRITE_LOG("%s: failed in write sz=%d errno=%d",
					  __func__, (int)write_size, errno);
				ret = INVALID;
				goto out;
			}
		}
		WRITE_LOG("num_blocks : %d start_addr %d num_read_blocks %d\n",
			  num_blocks, start_addr, num_read_blocks);
		num_blocks = num_blocks - num_read_blocks;
		start_addr = start_addr + num_read_blocks;

		if (num_blocks > max_num_blocks)
			num_read_blocks = max_num_blocks;
		else
			num_read_blocks = num_blocks;

		if (frames_out) {
			free(frames_out);
			frames_out = NULL;
		}
	}
out:
	if (frames_out)
		free(frames_out);
	if (ufs_bsg_fd != INVALID)
		close(ufs_bsg_fd);

	return ret;
}

static int do_write_rpmb(int fd, const unsigned char *key, int input_fd,
		__u32 cnt, __u16 start_addr, __u16 num_blocks, __u8 region)
{
	int ret = ERROR;
	unsigned char mac[RPMB_MAC_SIZE];
	struct rpmb_frame *frames_in = NULL;
	struct rpmb_frame frame_out = { 0 };
	ssize_t read_size = 0;
	__u8 max_num_blocks;
	__u8 num_write_blocks = 0;
	int i = 0;
	int j = 0;
	struct ufs_bsg_request bsg_req = { 0 };
	struct ufs_bsg_reply bsg_rsp = { 0 };
	int ufs_bsg_fd;
	__u8 data_buf[QUERY_DESC_GEOMETRY_MAX_SIZE] = { 0 };

	WRITE_LOG("Start : %s\n", __func__);

	ufs_bsg_fd = open(UFS_BSG_PATH, O_RDWR);
	if (ufs_bsg_fd != INVALID) {
		ret = do_read_desc(ufs_bsg_fd, &bsg_req, &bsg_rsp,
				   QUERY_DESC_IDN_GEOMETRY, 0,
				   QUERY_DESC_GEOMETRY_MAX_SIZE, data_buf);
	}

	if (ret) {
		printf("Warning: Cannot get bRPMB_ReadWriteSize");
		max_num_blocks = DEFAULT_RPMB_NUM_BLOCKS;
	} else {
		/*bRPMB_ReadWriteSize e.g 0x40 * 256 = 16K*/
		max_num_blocks = data_buf[0x17];
		if (max_num_blocks <= 0)
			max_num_blocks = 1;
		ret = OK;
	}

	if (num_blocks > max_num_blocks)
		num_write_blocks = max_num_blocks;
	else
		num_write_blocks = num_blocks;
	WRITE_LOG("max_num_blocks : %d num_block %d, cnt %d start_addr %d\n",
		max_num_blocks, num_write_blocks, cnt, start_addr);
	while (num_blocks > 0) {
		if (start_addr > MAX_ADDRESS) {
			print_error("Max available address is reached");
			goto out;
		}
		frames_in = (struct rpmb_frame *)calloc(num_write_blocks,
			     sizeof(struct rpmb_frame));
		if (!frames_in) {
			print_error("Cannot allocate %d RPMB frames",
					num_write_blocks);
			ret = -ENOMEM;
			goto out;
		}
		for (i = 0; i < num_write_blocks; i++) {
			frames_in[i].req_resp =      htobe16(RPMB_WRITE);
			frames_in[i].addr =	     htobe16(start_addr);
			frames_in[i].block_count =   htobe16(num_write_blocks);
			frames_in[i].write_counter = htobe32(cnt);
			read_size = read(input_fd, frames_in[i].data,
					RPMB_DATA_SIZE);
			if (read_size != RPMB_DATA_SIZE) {
				WRITE_LOG("%s: failed in read size=%d errno=%d",
					__func__, (int)read_size, errno);
				ret = EINVAL;
				goto out;
			}
		}

		rpmb_calc_hmac_sha256(frames_in, num_write_blocks,
				      key, RPMB_KEY_SIZE, mac, RPMB_MAC_SIZE);
		memcpy(frames_in[num_write_blocks - 1].key_mac,
			mac, RPMB_MAC_SIZE);

		ret = do_rpmb_op(fd, frames_in, num_write_blocks,
				&frame_out, 1, region);
		if (ret != 0)
			goto out;

		/* Check RPMB response */
		if (frame_out.result != 0) {
			print_operation_error(be16toh(frame_out.result));
			ret = -EINVAL;
			goto out;
		}

		WRITE_LOG("num_blocks : %d start_addr %d num_write_blocks %d ,"
			  "iter %d,cnt %d\n",
			  num_blocks, start_addr, num_write_blocks, j, cnt);
		num_blocks = num_blocks - num_write_blocks;
		start_addr = start_addr + num_write_blocks;
		if (num_blocks > max_num_blocks)
			num_write_blocks = max_num_blocks;
		else
			num_write_blocks = num_blocks;
		j++;
		cnt++;
		if (frames_in) {
			free(frames_in);
			frames_in = NULL;
		}

	}
out:
	if (ufs_bsg_fd != INVALID)
		close(ufs_bsg_fd);
	if (frames_in)
		free(frames_in);
	return ret;
}

static int do_read_conf_block(int fd, const unsigned char *key, __u8 lun,
			int output_fd)
{
	int ret = ERROR;
	ssize_t write_size;
	struct rpmb_frame frame_in = { 0 };
	struct rpmb_frame frame_out = { 0 };

	WRITE_LOG("Start : %s\n", __func__);

	frame_in.req_resp  = htobe16(RPMB_SEC_CONF_READ);
	frame_in.data[0] = lun;

	ret = do_rpmb_op(fd, &frame_in, 1, &frame_out, 1, 0);
	if (ret != 0) {
		print_error("Fail to read Secure Write Config Block");
		goto out;
	}
	if (frame_out.result != 0) {
		print_operation_error(be16toh(frame_out.result));
		goto out;
	}

	if (key != NULL) {
		__u8 mac[RPMB_MAC_SIZE];

		rpmb_calc_hmac_sha256(&frame_out, 1, key,
			RPMB_KEY_SIZE, mac, RPMB_MAC_SIZE);
		/* Compare calculated MAC and MAC from last frame
		 * Note the mac much only in case we read 1 block , otherwise the mac
		 * field is not much, in all frame ,include the last one */
		if (memcmp(mac, frame_out.key_mac, sizeof(mac)))
			print_error("Warning: RPMB MAC mismatch mac");
	}
	write_size = write(output_fd, frame_out.data, RPMB_DATA_SIZE);
	if (write_size != RPMB_DATA_SIZE) {
		WRITE_LOG("%s: failed in write size=%d errno=%d",
			  __func__, (int)write_size, errno);
		ret = ERROR;
	} else
		printf("Secure Write Protect Config Block was read\n");
out:
		return ret;
}

static int do_write_conf_block(int fd, const unsigned char *key, int input_fd,
		__u32 cnt)
{
	int ret = INVALID;
	__u8 mac[RPMB_MAC_SIZE];
	struct rpmb_frame frame_in = { 0 };
	struct rpmb_frame frame_out = { 0 };
	ssize_t read_size = 0;

	WRITE_LOG("Start : %s\n", __func__);

	frame_in.req_resp =      htobe16(RPMB_SEC_CONF_WRITE);
	frame_in.block_count =   htobe16(1);
	frame_in.write_counter = htobe32(cnt);
	read_size = read(input_fd, frame_in.data, RPMB_DATA_SIZE);
	if (read_size != RPMB_DATA_SIZE) {
		WRITE_LOG("%s: failed in read size=%d errno=%d",
			__func__, (int)read_size, errno);
		ret = INVALID;
		goto out;
	}

	rpmb_calc_hmac_sha256(&frame_in, 1,
		key, RPMB_KEY_SIZE, mac, RPMB_MAC_SIZE);
	memcpy(frame_in.key_mac, mac, RPMB_MAC_SIZE);

	ret = do_rpmb_op(fd, &frame_in, 1, &frame_out, 1, 0);
	if (ret != 0) {
		print_error("Fail to write Secure Write Config Block");
		goto out;
	}

	/* Check RPMB response */
	if (frame_out.result != 0) {
		print_operation_error(be16toh(frame_out.result));
		ret = -EINVAL;
	} else
		printf("Secure Write Protect Config Block was written\n");

out:
		return ret;
}

static unsigned char *get_auth_key(char *key_path)
{
	unsigned char *pkey = NULL;
	int key_fd = INVALID;
	ssize_t read_size;

	if (key_path == NULL)
		return NULL;

	key_fd = open(key_path, O_RDONLY);
	if (key_fd < 0) {
		perror("Key file open");
	} else {
		read_size = read(key_fd, key, RPMB_KEY_SIZE);
		if (read_size < RPMB_KEY_SIZE) {
			print_error("Key must be %d bytes length,was read %d",
				    RPMB_KEY_SIZE, read_size);
		} else
			pkey = key;
	}

	if (key_fd != INVALID)
		close(key_fd);
	return pkey;
}

int do_rpmb(struct tool_options *opt)
{
	int rc = INVALID;
	int fd;
	int output_fd = INVALID;
	unsigned char *key_ptr = NULL;
	__u32 cnt = 0;
	__u8 lun;

	fd = open(opt->path, O_RDWR | O_SYNC);
	if (fd < 0) {
		perror("open");
		return ERROR;
	}

	switch (opt->idn) {
	case AUTHENTICATION_KEY:
		key_ptr = get_auth_key(opt->keypath);
		if (key_ptr == NULL)
			goto out;
		rc = do_key(fd, key_ptr, opt->region);
	break;
	case READ_WRITE_COUNTER:
		rc = do_read_counter(fd, &cnt, opt->region, true);
		break;
	case READ_RPMB:
		output_fd = open(opt->data, O_WRONLY | O_CREAT | O_SYNC,
				 S_IRUSR | S_IWUSR);
		if (output_fd < 0) {
			perror("Output file open");
			goto out;
		}
		if (opt->keypath[0] != 0) {
			key_ptr = get_auth_key(opt->keypath);
			if (key_ptr == NULL)
				goto out;
		}

		rc = do_read_rpmb(fd, output_fd, key_ptr, opt->start_block,
				  opt->num_block, opt->region);
		if (!rc)
			printf("Finish to read RPMB data\n");
	break;
	case WRITE_RPMB:
		key_ptr = get_auth_key(opt->keypath);
		if (key_ptr == NULL)
			goto out;

		output_fd = open(opt->data, O_RDONLY | O_SYNC);
		if (output_fd < 0) {
			perror("Input file open");
			goto out;
		}
		rc = do_read_counter(fd, &cnt, opt->region, false);
		if (rc)
			goto out;
		rc = do_write_rpmb(fd, key_ptr, output_fd, cnt,
				opt->start_block, opt->num_block, opt->region);
		if (!rc)
			printf("Finish to write RPMB data\n");
	break;
	case READ_SEC_RPMB_CONF_BLOCK:
		lun = opt->lun;
		if (opt->keypath[0] != 0) {
			key_ptr = get_auth_key(opt->keypath);
			if (key_ptr == NULL)
				goto out;
		}

		output_fd = open(opt->data, O_WRONLY | O_CREAT | O_SYNC,
				 S_IRUSR | S_IWUSR);
		if (output_fd < 0) {
			perror("Output file open");
			goto out;
		}

		rc = do_read_conf_block(fd, key_ptr, lun, output_fd);
	break;
	case WRITE_SEC_RPMB_CONF_BLOCK:
		key_ptr = get_auth_key(opt->keypath);
		if (key_ptr == NULL)
			goto out;

		output_fd = open(opt->data, O_RDONLY | O_SYNC);
		if (output_fd < 0) {
			perror("Input file open");
			goto out;
		}
		rc = do_read_counter(fd, &cnt, 0, false);
		if (rc)
			goto out;

		rc = do_write_conf_block(fd, key_ptr, output_fd, cnt);
	break;
	default:
		print_error("Unsupported RPMB cmd %d", opt->idn);
	break;
	}
out:
	if (output_fd != INVALID)
		close(output_fd);
	close(fd);
	return rc;
}

void rpmb_help(char *tool_name)
{
	printf("\n RPMB command usage:\n");
	printf("\n\t%s rpmb [-t] <rpmb cmd idn> [-p] <path to device>"
		" -k <path to device> -l <lun> -d <output/input file.\n",
		tool_name);
	printf("\n\t-t\t RPMB cmd type idn\n"
		"\t\t\t0:\tKey provision\n"
		"\t\t\t1:\tRead Write counter\n"
		"\t\t\t2:\tRead RPMB data\n"
		"\t\t\t3:\tWrite RPMB data\n"
		"\t\t\t4:\tSecure Write Protect Configuration Block Write\n"
		"\t\t\t5:\tSecure Write Protect Configuration Block Read\n");

	printf("\n\t-s\t RPMB start address (default value is 0)\n");
	printf("\n\t-n\t number of RPMB read/write blocks (default value is 1)\n");
	printf("\n\t-p\t device path (RPMB LUN)\n");
	printf("\n\t-k\t path to RPMB key, "
		"the key path must pass to the tool in case of writing to RPMB,\n"
		"\t\t in case of reading from RPMB ,the key may pass,"
		" in case we want to validate the MAC\n"
		"\t\t in case we want to validate the hash value\n");
	printf("\n\t-l\t lun number(byte) using as parameter "
		"for Secure Write Config Read\n");
	printf("\n\t-w\t path to data file\n");
	printf("\n\t-m\t RPMB region.\n");
	printf("\n\tExample - Read 16MB of data from RPMB LUN started "
		"from address 0 to output file\n"
		"\t\t  %s rpmb -t 2 -p /dev/0:0:0:49476 -s 0 -n 65536 -w output_file\n",
		tool_name);
	printf("\n\tExample - Write RPMB key\n"
		"\t\t  %s rpmb -t 0 -p /dev/0:0:0:49476 -k key_file\n",
		tool_name);
	printf("\n\tExample - Write RPMB key to region 2\n"
		"\t\t  %s rpmb -t 0 -m 2 -p /dev/0:0:0:49476 -k key_file\n",
		tool_name);
	printf("\n\tExample - Write Secure Write Config block\n"
		"\t\t  The input file is Secure Write Config block filled "
		"according to the spec\n"
		"\t\t  %s rpmb -t 4 -p /dev/0:0:0:49476  -w input_file\n",
		tool_name);
	printf("\n\tExample - Read Secure Write Config block\n"
		"\t\t  After the command successfully finished , "
		"the output file will contains\n"
		"\t\t  Secure Write Config block of lun 1\n"
		"\t\t  %s rpmb -t 5 -p /dev/0:0:0:49476  -l 1 -d output_file\n",
		tool_name);
}
