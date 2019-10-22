// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2017 Micron Technology Inc.
 *
 * Author:
 *	Bean Huo <beanhuo@micron.com>
 *
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdint.h>
#include <errno.h>

#include "ufs.h"
#include "options.h"
#include "scsi_bsg_util.h"
#include "rpmb.h"
#include "hmac_sha/hmac_sha2.h"

static int read_rpmb_status(struct rpmb_opt *opt);
static int rpmb_read_counter(struct rpmb_opt *opt);
static int rpmb_program_key(struct rpmb_opt *opt);
static int rpmb_data_read(struct rpmb_opt *opt);
static int rpmb_data_write(struct rpmb_opt *opt);
static int cfg_blk_read(struct rpmb_opt *opt);
static int cfg_blk_write(struct rpmb_opt *opt);

static struct ufs_rpmb_type rpmb_op_t[] = {
	{"status", RPMB_STATUS, read_rpmb_status},
	{"read_counter", RPMB_READ_COUNTER, rpmb_read_counter},
	{"write_key", RPMB_PROGRAM_KEY, rpmb_program_key},
	{"read_data", RPMB_DATA_READ, rpmb_data_read},
	{"write_data", RPMB_DATA_WRITE, rpmb_data_write},
	{"write_cfg", RPMB_CFG_BLK_WRITE, cfg_blk_write},
	{"read_cfg", RPMB_CFG_BLK_READ, cfg_blk_read}
};

#define DO_IO(func, fd, buf, nbyte)				\
	({							\
		ssize_t ret = 0, r;				\
		do {						\
			r = func(fd, buf + ret, nbyte - ret);   \
			if (r < 0 && errno != EINTR) {		\
				ret = -1;			\
				break;				\
			}  else if (r > 0)			\
				ret += r;			\
		} while (r != 0 && (size_t)ret != nbyte);	\
		ret;						\
	 })

static void dump_buffer(char *msg, const __u8 *buf, __u32 len)
{
	__u32 i;

	if (msg)
		printf("%s:\n", msg);
	for (i = 0; i < len; i++) {
		printf("0x%02x ", buf[i]);
		if (!((i + 1) % 16))
			printf("\n");
	}
}

/*
 * RPMB Operation Result, which is composed of two bytes.
 * More details please refer to Table 12.8 in UFS Spec.
 */
static const char *const rpmb_result_str[] = {
	"Operation OK", /* 0000h (0080h) */
	"General failure", /* 0001h (0081h) */
	"Authentication failure", /* 0002h (0082h) */
	"Counter failure", /* 0003h (0083h) */
	"Address failure", /* 0004h (0084h) */
	"Write failure", /* 0005h (0085h) */
	"Read failure", /* 0006h (0086h) */
	"Key not yet programmed", /* 0007h */
	"SWP Configuration Block access failure", /* 0008h (0088h) */
	"Invalid SWP Configuration parameter", /* 0009h (0089h) */
	"SWP not applicable", /* 000Ah (008Ah) */
};

static void generate_mac(struct rpmb_mesg_frame *frames_out,
			 __u8 *mac, __u8 *key, __u32 cnt)
{
	hmac_sha256_ctx ctx;
	__u32 i;

	hmac_sha256_init(&ctx, key, RPMB_MSG_KEY_SIZE);
	for (i = 0; i < cnt; i++) {
		hmac_sha256_update(&ctx, frames_out[i].data,
				   RPMB_INPUT_SIZE_FOR_MAC);
	}
	hmac_sha256_final(&ctx, mac, RPMB_MSG_KEY_SIZE);
}

static int read_key(char *key_path, __u8 *key)
{
	struct stat st;
	int key_size;
	int key_fd = INVALID;
	int rt = ERROR;

	if (key_path[0] != '\0') {
		if (!strcmp("-", key_path)) {
			key_fd = STDIN_FILENO;
		} else {
			key_fd = open(key_path, O_RDONLY);
			if (key_fd < 0) {
				perror("key file open failed");
				return rt;
			}
		}
	}

	if (key_fd != STDIN_FILENO) {
		if (fstat(key_fd, &st) < 0)
			goto out;

		key_size = st.st_size - 1; /* exclude EOF*/

		if (key_size <= 0 ||
		    key_size > RPMB_MSG_KEY_SIZE) {
			print_error("Invalid RPMB key size %d in key file",
				    key_size);
			goto out;
		}
	}

	rt = DO_IO(read, key_fd, key, RPMB_MSG_KEY_SIZE);
	if (rt < 0) {
		print_error("Read the key failed");
	} else if (rt != RPMB_MSG_KEY_SIZE) {
		print_error("Read %d bytes, auth key must be %lu bytes length",
			    rt,
			    RPMB_MSG_KEY_SIZE);
		rt = ERROR;
	} else {
		rt = OK;
	}
out:
	if (key_fd != INVALID && key_fd != STDIN_FILENO)
		close(key_fd);

	return rt;
}

/*
 * submit_sec_cdb - Used to send SECURITY PROTOCOL OUT/IN CDB
 * @fd: bsg driver file descriptor
 * @spsp: SECURITY PROTOCOL SPECIFIC in CDB
 * @secp: SECURITY PROTOCOL in CDB
 * @buf: pointer to the SCSI cmd data buffer
 * @len: SCSI data length
 * @send: The cmd direction, True or 1 for send, False or 0 for read
 */
static int submit_sec_cdb(int fd, __u16 spsp, __u8 secp, char *buf,
		int len, _Bool send)
{
	int ret;
	unsigned char cdb[SEC_PROTOCOL_CMDLEN] = {0};

	cdb[0] = send ? SECURITY_PROTOCOL_OUT : SECURITY_PROTOCOL_IN;
	cdb[1] = secp;

	*(__u16 *)&cdb[2] = htobe16(spsp);
	*(__u32 *)&cdb[6] = htobe32(len);
#if defined(DEBUG)
	dump_buffer("CDB Raw data", cdb, SEC_PROTOCOL_CMDLEN);
	if (send)
		dump_buffer("Sending", (__u8 *)buf, len);
#endif
	ret = send_bsg_scsi_cmd(fd, cdb, buf,
			SEC_PROTOCOL_CMDLEN, len,
			(send ? SG_DXFER_TO_DEV : SG_DXFER_FROM_DEV));

	if (ret < 0) {
		print_error("SG_IO %s error ret %d",
			    (send ? "SECURITY_PROTOCOL_OUT" :
			    "SECURITY_PROTOCOL_IN"),
			    ret);
		goto out;
	}
#if defined(DEBUG)
	if (!send)
		dump_buffer("Received", (__u8 *)buf, len);
#endif
out:
	return ret;
}

static int execute_read_write(int bsg_fd, struct rpmb_mesg_frame *msg_in,
			      struct rpmb_mesg_frame *msg_out, __u32 cnt,
			      __u8 region, __u16 req_type)
{
	int rt = ERROR;
	__u16 expected_rsp;
	__u16 result;
	struct rpmb_mesg_frame rpmb_status = {0};
	__u16 sec_spec = (region << 8) | UFS_SECURITY_PROTOCOL_SPECIFIC;

	expected_rsp = req_type << 8;

	switch (req_type) {
	case RPMB_KEY_WRITE_REQ:
	case RPMB_WRITE_REQ:
	case SEC_PROT_CFG_BLK_WRITE:
		/*
		 * Step 1: Programming request
		 */
		rt = submit_sec_cdb(bsg_fd,
				    sec_spec,
				    UFS_SECURITY_PROTOCOL,
				    (char *)msg_in,
				    (cnt * RPMB_MSG_SIZE),
				    1);
		if (rt < 0) {
			print_error("Failed to send programming request");
			goto out;
		}
		/*
		 * Step 2: Result read request
		 */
		rpmb_status.req_resp = htobe16(RPMB_RESULT_RD_REQ);
		rt = submit_sec_cdb(bsg_fd,
				    sec_spec,
				    UFS_SECURITY_PROTOCOL,
				    (char *)&rpmb_status,
				    RPMB_MSG_SIZE, 1);
		if (rt < 0) {
			print_error("Failed to send result read request");
			goto out;
		}
		/*
		 * Step 3: Result read response
		 */
		rt = submit_sec_cdb(bsg_fd,
				    sec_spec,
				    UFS_SECURITY_PROTOCOL, (char *)msg_out,
				    RPMB_MSG_SIZE, 0);
		if (rt < 0) {
			print_error("Failed to read response");
			print_error("rt:%d, result:0x%x, req_resp: 0x%x",
				    rt,
				    be16toh(msg_out->result),
				    be16toh(msg_out->req_resp));
			goto out;
		}
		break;
	case RPMB_WC_READ_REQ:
	case RPMB_READ_REQ:
	case SEC_PROT_CFG_BLK_READ:
		/*
		 * Step 1: Send read request
		 */
		rt = submit_sec_cdb(bsg_fd,
				    sec_spec,
				    UFS_SECURITY_PROTOCOL, (char *)msg_in,
				    RPMB_MSG_SIZE, 1);
		if (rt < 0) {
			print_error("Failed to send read request");
			goto out;
		}
		/*
		 * Step 2: Read response
		 */
		rt = submit_sec_cdb(bsg_fd,
				    sec_spec,
				    UFS_SECURITY_PROTOCOL, (char *)msg_out,
				    (cnt * RPMB_MSG_SIZE), 0);
		if (rt < 0) {
			print_error("Failed to read response");
			goto out;
		}
		break;
	default:
		print_error("Unknown RPMB request type");
		rt = -EINVAL;
		goto out;
	}

	result = be16toh(msg_out[cnt - 1].result);
	if (result != 0x0000) {
		const char *result_str;

		if ((result & 0x000F) < ARRAY_SIZE(rpmb_result_str))
			result_str = rpmb_result_str[result & 0x000F];
		else
			result_str = "Unkown result code";

		print_error("RPMB response got error result:%s, 0x%x",
				result_str, result);
		rt = ERROR;
		goto out;
	}
	if (be16toh(msg_out->req_resp) != expected_rsp) {
		print_error("RPMB response mismatch");
		printf("Received: 0x%x, expected 0x%x",
		       expected_rsp,
		       be16toh(msg_out->req_resp));
		rt = ERROR;
	}
out:
	return rt;
}

static int rpmb_program_key(struct rpmb_opt *opt)
{
	int rt = ERROR;
	int bsg_fd = INVALID;
	struct rpmb_mesg_frame rpmb_msg_in = {0};
	struct rpmb_mesg_frame rpmb_msg_out = {0};
	__u8 region;

	bsg_fd = open(opt->bsg_path, O_RDWR);
	if (bsg_fd < 0) {
		print_error("Failed to open RPMB bsg device");
		return rt;
	}
	/*
	 * Read key
	 */
	rt = read_key(opt->key_path, rpmb_msg_in.key_mac);
	if (rt) {
		print_error("Failed to read key");
		goto out;
	}
	/*
	 * Auth Key Programming
	 */
	region = opt->region;
	rpmb_msg_in.req_resp = htobe16(RPMB_KEY_WRITE_REQ);
	rt = execute_read_write(bsg_fd, &rpmb_msg_in, &rpmb_msg_out, 1,
				region, RPMB_KEY_WRITE_REQ);
	if (rt < 0)
		print_error("execute_read_write() failed in %s", __func__);
out:
	close(bsg_fd);
	return rt;
}

static int read_rpmb_status(struct rpmb_opt *opt)
{
	int rt = ERROR;
	int bsg_fd = INVALID;
	__u8 buf[18] = {0};

	bsg_fd = open(opt->bsg_path, O_RDWR);
	if (bsg_fd < 0) {
		print_error("Failed to open RPMB bsg device");
		return rt;
	}

	rt = ufs_request_sense(bsg_fd, buf, 18);
	if (rt < 0) {
		print_error("ufs_request_sense() ret %d", rt);
	} else {
		if (buf[2] == 0)
			printf("RPMB UNIT is ready\n");
		else
			print_error("RPMB encounted error, SENSE KEY: 0x%x\n",
					buf[2]);
		dump_buffer("RPMB LUN sense data", buf, 18);
	}

	close(bsg_fd);
	return 0;
}

static int verify_data_with_local_key(struct rpmb_mesg_frame *frames_out,
				      __u8 *key, __u32 cnt)
{
	int rt = ERROR;
	__u8 mac[RPMB_MSG_KEY_SIZE];

	generate_mac(frames_out, mac, key, cnt);

	if (memcmp(mac, frames_out[cnt - 1].key_mac, RPMB_MSG_KEY_SIZE)) {
		print_error("RPMB MAC mismatch");
		dump_buffer("Recived MAC", frames_out[cnt - 1].key_mac,
				RPMB_MSG_KEY_SIZE);
		dump_buffer("Expected MAC", mac, RPMB_MSG_KEY_SIZE);
	} else {
		rt = OK;
	}

	return rt;
}

static int do_read_counter(int bsg_fd, char *key_path, __u8 region,
			   __u32 *counter, _Bool need_check)
{
	int rt = ERROR;
	__u8 key[RPMB_MSG_KEY_SIZE];
	struct rpmb_mesg_frame rpmb_msg_in = {0};
	struct rpmb_mesg_frame rpmb_msg_out = {0};

	rpmb_msg_in.req_resp = htobe16(RPMB_WC_READ_REQ);
	rt = execute_read_write(bsg_fd, &rpmb_msg_in,
				&rpmb_msg_out, 1,
				region, RPMB_WC_READ_REQ);
	if (rt < 0) {
		print_error("execute_read_write() failed in %s", __func__);
		goto out;
	}

	if (need_check && (key_path[0] != '\0')) {
		rt = read_key(key_path, key);
		if (rt) {
			print_error("Failed to read key");
			goto out;
		}
		if (memcmp(&rpmb_msg_in.nonce,
			   &rpmb_msg_out.nonce,
			   RPMB_MSG_NONCE_SIZE)) {
			print_error("RPMB NONCE mismatch");
			goto out;
		}
		rt = verify_data_with_local_key(&rpmb_msg_out, key, 1);
		if (rt) {
			print_error("MAC verification failed");
			goto out;
		}
	}

	*counter = be32toh(rpmb_msg_out.write_counter);
out:
	return rt;
}

static int rpmb_read_counter(struct rpmb_opt *opt)
{
	int rt = ERROR;
	int bsg_fd = INVALID;
	__u32 counter;

	bsg_fd = open(opt->bsg_path, O_RDWR);
	if (bsg_fd < 0) {
		print_error("Failed to open bsg device");
		return rt;
	}

	rt = do_read_counter(bsg_fd, opt->key_path, opt->region, &counter, 1);
	if (rt < 0)
		print_error("Read RPMB Region_%d write_counter failed",
				opt->region);
	else
		printf("\n\tRPMB Region_%d wirite counter: 0x%02x\n\n",
				opt->region, counter);

	close(bsg_fd);
	return rt;
}

/*
 * Authenticated Secure Write Protect Configuration Block Read
 */
static int cfg_blk_read(struct rpmb_opt *opt)
{
	int rt = ERROR;
	int bsg_fd = INVALID, out_fd = INVALID;
	struct rpmb_mesg_frame rpmb_msg_in = {0};
	struct rpmb_mesg_frame rpmb_msg_out = {0};
	__u8 key[RPMB_MSG_KEY_SIZE];
	__u8 lun;

	lun = opt->lun;

	bsg_fd = open(opt->bsg_path, O_RDWR);
	if (bsg_fd < 0) {
		print_error("Failed to open RPMB bsg device");
		goto out;
	}

	rpmb_msg_in.req_resp = htobe16(SEC_PROT_CFG_BLK_READ);
	rpmb_msg_in.block_count = htobe16(0x0001);
	rpmb_msg_in.cfg_blk.lun = lun;

	rt = execute_read_write(bsg_fd, &rpmb_msg_in, &rpmb_msg_out,
				1, 0, SEC_PROT_CFG_BLK_READ);
	if (rt < 0) {
		print_error("execute_read_write() failed in %s", __func__);
		goto out;
	}

	/*
	 * Read key, and verify data
	 */
	if (opt->key_path[0] != '\0') {
		rt = read_key(opt->key_path, key);
		if (rt) {
			print_error("Failed to read key");
			goto out;
		}
		if (memcmp(&rpmb_msg_in.nonce, &rpmb_msg_out.nonce,
			   RPMB_MSG_NONCE_SIZE)) {
			print_error("RPMB NONCE mismatch");
			goto out;
		}
		rt = verify_data_with_local_key(&rpmb_msg_out, key, 1);
		if (rt) {
			print_error("MAC verification failed");
			goto out;
		}
	}
	/*
	 * Output data
	 */
	if (!strcmp(opt->io_file, "-")) {
		/* Output data to STDIO */
		printf("\nWrite Protect Configuration Block on LUN %d:\n", lun);
		printf("DATA LENGTH: %d\n", rpmb_msg_out.cfg_blk.data_len);
		dump_buffer("Secure Write Protect Entry 0",
				rpmb_msg_out.cfg_blk.entry_0, 16);
		dump_buffer("Secure Write Protect Entry 1",
				rpmb_msg_out.cfg_blk.entry_1, 16);
		dump_buffer("Secure Write Protect Entry 2",
				rpmb_msg_out.cfg_blk.entry_2, 16);
		dump_buffer("Secure Write Protect Entry 3",
				rpmb_msg_out.cfg_blk.entry_3, 16);
	} else {
		/* Output to file */
		out_fd = open(opt->io_file,
			      O_WRONLY | O_CREAT | O_APPEND, 0600);
		if (out_fd < 0) {
			print_error("Can't open output file");
			goto out;
		}
		rt = DO_IO(write, out_fd, rpmb_msg_out.cfg_blk.entry_0,
				 64);
		if (rt < 0) {
			print_error("Failed to write SWPC block data to file");
			goto out;
		}
	}
out:
	close(bsg_fd);
	if (out_fd != STDOUT_FILENO)
		close(out_fd);

	return rt;
}

static int rpmb_data_read(struct rpmb_opt *opt)
{
	int rt = ERROR;
	int bsg_fd = INVALID, out_fd = INVALID;
	struct rpmb_mesg_frame rpmb_msg_in = {0};
	struct rpmb_mesg_frame *rpmb_msg_out = NULL;
	__u8 key[RPMB_MSG_KEY_SIZE];
	__u16 blk_cnt, addr;
	__u8 region;

	if (opt->block_counts == INVALID || opt->block_counts == 0) {
		print_error("block_counts specified is not proper");
		return rt;
	}

	addr = opt->addr;
	blk_cnt = opt->block_counts;
	region = opt->region;

	rpmb_msg_out =
		(struct rpmb_mesg_frame *)calloc(blk_cnt, RPMB_MSG_SIZE);
	if (!rpmb_msg_out) {
		print_error("Failed to allocate rpmb_mesg_frame");
		rt = -ENOMEM;
		return rt;
	}

	bsg_fd = open(opt->bsg_path, O_RDWR);
	if (bsg_fd < 0) {
		print_error("Failed to open RPMB bsg device");
		goto out;
	}

	rpmb_msg_in.req_resp = htobe16(RPMB_READ_REQ);
	rpmb_msg_in.addr = htobe16(addr);
	rpmb_msg_in.block_count = htobe16(blk_cnt);
	rt = execute_read_write(bsg_fd, &rpmb_msg_in, rpmb_msg_out,
				blk_cnt, region, RPMB_READ_REQ);
	if (rt < 0) {
		print_error("execute_read_write() failed in %s", __func__);
		goto out;
	}

	/*
	 * Read key, and verify data
	 */
	if (opt->key_path[0] != '\0') {
		rt = read_key(opt->key_path, key);
		if (rt) {
			print_error("Failed to read key");
			goto out;
		}
		if (memcmp(&rpmb_msg_in.nonce, &rpmb_msg_out[blk_cnt - 1].nonce,
			   RPMB_MSG_NONCE_SIZE)) {
			print_error("RPMB NONCE mismatch");
			goto out;
		}
		rt = verify_data_with_local_key(rpmb_msg_out, key, blk_cnt);
		if (rt) {
			print_error("MAC verification failed");
			goto out;
		}
	}
	/*
	 * Output data
	 */
	if (!strcmp(opt->io_file, "-")) {
		out_fd = STDOUT_FILENO;
	} else {
		out_fd = open(opt->io_file,
			      O_WRONLY | O_CREAT | O_APPEND, 0600);
		if (out_fd < 0) {
			print_error("Can't open output file");
			goto out;
		}
	}
	int i;

	for (i = 0; i < blk_cnt; i++) {
		if (out_fd != STDOUT_FILENO) {
			rt = DO_IO(write, out_fd, rpmb_msg_out[i].data,
					RPMB_MSG_DATA_SIZE);
			if (rt < 0) {
				print_error("Failed to output data");
				goto out;
			}
		} else {
			char str[80];

			sprintf(str, "\nData in RPMB Region_%d, Addr 0x%08x",
				region, (addr + i * RPMB_MSG_DATA_SIZE));
			dump_buffer(str, rpmb_msg_out[i].data,
					RPMB_MSG_DATA_SIZE);
		}
	}

out:
	free(rpmb_msg_out);
	close(bsg_fd);
	if (out_fd != STDOUT_FILENO)
		close(out_fd);

	return rt;
}

/*
 * Authenticated Secure Write Protect Configuration Block write
 */
static int cfg_blk_write(struct rpmb_opt *opt)
{
	int rt = ERROR;
	int bsg_fd = INVALID, file_fd = INVALID;
	__u16 entry_cnt;
	__u32 write_counter;
	struct rpmb_mesg_frame rpmb_msg_in = {0};
	struct rpmb_mesg_frame rpmb_msg_out = {0};
	__u8 key[RPMB_MSG_KEY_SIZE];
	__u8 lun, length;

	if (opt->block_counts <= 0) {
		print_error("Entry count specified is not proper");
		return rt;
	}
	if (opt->io_file[0] == '\0') {
		print_error("Input file missed");
		return rt;
	}

	entry_cnt = opt->block_counts;
	length = entry_cnt * 16;
	lun = opt->lun;

	bsg_fd = open(opt->bsg_path, O_RDWR);
	if (bsg_fd < 0) {
		print_error("Failed to open RPMB device");
		return rt;
	}
	/*
	 * Read Key
	 */
	rt = read_key(opt->key_path, key);
	if (rt) {
		print_error("Failed to read key");
		goto out;
	}

	file_fd = open(opt->io_file, O_RDONLY);
	if (bsg_fd < 0) {
		print_error("Failed to open input file");
		goto out;
	}

	rt = do_read_counter(bsg_fd, opt->key_path, 0,
			(__u32 *)&write_counter, 1);
	if (rt < 0) {
		print_error("Failed to read RPMB write_counter");
		goto out;
	}

	rpmb_msg_in.write_counter = htobe32(write_counter);
	rpmb_msg_in.block_count = htobe16(0x0001);
	rpmb_msg_in.req_resp = htobe16(SEC_PROT_CFG_BLK_WRITE);
	rpmb_msg_in.cfg_blk.lun = lun;
	rpmb_msg_in.cfg_blk.data_len = length;

	rt  = DO_IO(read, file_fd, rpmb_msg_in.cfg_blk.entry_0, length);
	if (rt < 0) {
		print_error("Failed to read data from cfg_blk file");
		goto out;
	}

	generate_mac(&rpmb_msg_in, rpmb_msg_in.key_mac,
		     key, 1);

	rt = execute_read_write(bsg_fd, &rpmb_msg_in, &rpmb_msg_out, 1,
				0, SEC_PROT_CFG_BLK_WRITE);
	if (rt < 0)
		print_error("execute_read_write() failed in %s", __func__);

out:
	if (bsg_fd >= 0)
		close(bsg_fd);
	if (file_fd >= 0)
		close(file_fd);
	return rt;
}

static int rpmb_data_write(struct rpmb_opt *opt)
{
	int rt = ERROR;
	int bsg_fd = INVALID, file_fd = INVALID;
	__u16 blk_cnt, addr;
	__u32 write_counter;
	struct rpmb_mesg_frame *rpmb_msg_in = NULL;
	struct rpmb_mesg_frame rpmb_msg_out = {0};
	__u8 key[RPMB_MSG_KEY_SIZE];
	__u32 i;
	__u8 region;

	if (opt->addr == INVALID) {
		print_error("Accessed address is invalid");
		return rt;
	}
	if (opt->block_counts == INVALID || opt->block_counts == 0) {
		print_error("block_counts specified is not proper");
		return rt;
	}
	if (opt->io_file[0] == '\0') {
		print_error("didn't specify input");
		return rt;
	}

	blk_cnt = opt->block_counts;
	addr = opt->addr;
	region = opt->region;

	bsg_fd = open(opt->bsg_path, O_RDWR);
	if (bsg_fd < 0) {
		print_error("Failed to open RPMB device");
		return rt;
	}
	/*
	 * Read Key
	 */
	rt = read_key(opt->key_path, key);
	if (rt) {
		print_error("Failed to read key");
		goto out;
	}

	file_fd = open(opt->io_file, O_RDONLY);
	if (file_fd < 0) {
		print_error("Failed to open input file");
		goto out;
	}

	rpmb_msg_in = (struct rpmb_mesg_frame *)calloc(blk_cnt, RPMB_MSG_SIZE);
	if (!rpmb_msg_in) {
		print_error("Failed to allocate rpmb_mesg_frame");
		rt = -ENOMEM;
		goto out;
	}
	memset(rpmb_msg_in, 0, blk_cnt * RPMB_MSG_SIZE);

	rt = do_read_counter(bsg_fd, opt->key_path, opt->region,
			(__u32 *)&write_counter, 1);
	if (rt < 0) {
		print_error("Failed to read RPMB write_counter");
		goto out;
	}

	for (i = 0; i < blk_cnt; i++) {
		rpmb_msg_in[i].write_counter = htobe32(write_counter);
		rpmb_msg_in[i].addr = htobe16(addr);
		rpmb_msg_in[i].block_count = htobe16(blk_cnt);
		rpmb_msg_in[i].req_resp = htobe16(RPMB_WRITE_REQ);

		rt  = DO_IO(read, file_fd, rpmb_msg_in[i].data,
			    RPMB_MSG_DATA_SIZE);
		if (rt < 0) {
			print_error("Failed to read data from input file");
			goto out;
		}
	}

	generate_mac(rpmb_msg_in, rpmb_msg_in[blk_cnt - 1].key_mac,
		     key, blk_cnt);

	rt = execute_read_write(bsg_fd, rpmb_msg_in, &rpmb_msg_out, blk_cnt,
				region, RPMB_WRITE_REQ);
	if (rt < 0)
		print_error("execute_read_write() failed in %s", __func__);

out:
	if (bsg_fd >= 0)
		close(bsg_fd);
	if (file_fd >= 0)
		close(file_fd);
	if (rpmb_msg_in)
		free(rpmb_msg_in);
	return rt;
}

static int check_op_type(const char *name, struct rpmb_opt *op,
		int (**func)(struct rpmb_opt *))
{
	int rt = INVALID;
	int i;

	for (i = 0; i < ARRAY_SIZE(rpmb_op_t); i++) {
		if (!strcmp(name, rpmb_op_t[i].name)) {
			if (op->type == INVALID) {
				op->type = rpmb_op_t[i].type;
				*func = rpmb_op_t[i].func;
				rt = OK;
			} else {
				print_error("Duplicate rpmb operation type");
			}
			break;
		}
	}

	return rt;
}

int check_path(char *dest, char *path)
{
	if (dest[0] != '\0') {
		print_error("Duplicate path");
		goto out;
	}

	if (!optarg || optarg[0] == 0) {
		print_error("Path missed");
		goto out;
	}

	strcpy(dest, path);
	return OK;
out:
	return INVALID;
}

/*
 * Check logical UNIT number
 */
static int check_lun(struct rpmb_opt *op)
{
	int rt = OK;

	if (strstr(optarg, "0x") || strstr(optarg, "0X"))
		op->lun = (int)strtol(optarg, NULL, 0);
	else
		op->lun = atoi(optarg);

	if (op->lun > 32 || op->lun < 0) {
		print_error("Invalid argument for LUN");
		rt = INVALID;
	}

	return rt;
}

/*
 * Check RPMB region number
 */
static int check_rpmb_region(struct rpmb_opt *op)
{
	int rt = OK;

	if (strstr(optarg, "0x") || strstr(optarg, "0X"))
		op->region = (int)strtol(optarg, NULL, 0);
	else
		op->region = atoi(optarg);

	if (op->region > 3 || op->region < 0) {
		print_error("Invalid argument for RPMB region");
		rt = INVALID;
	}

	return rt;
}

static int check_block_count(struct rpmb_opt *op)
{
	int rt = OK;

	if (strstr(optarg, "0x") || strstr(optarg, "0X"))
		op->block_counts = (int)strtol(optarg, NULL, 0);
	else
		op->block_counts = atoi(optarg);

	if (!optarg ||
	    (op->block_counts == 0 && strcmp(optarg, "0")) ||
	    op->block_counts < 0) {
		print_error("Invalid argument for block count");
		rt = INVALID;
	}

	return rt;
}

static int check_address(struct rpmb_opt *op)
{
	int rt = OK;

	if (strstr(optarg, "0x") || strstr(optarg, "0X"))
		op->addr = (int)strtol(optarg, NULL, 0);
	else
		op->addr = atoi(optarg);

	return rt;
}

static int rpmb_parser(int argc, char **argv, struct rpmb_opt *op,
		int (**func)(struct rpmb_opt *))
{
	int rt = -EINVAL;
	int curr_opt = 0;
	int index = 0;

	static struct option long_opts[] = {
		{"read_counter", no_argument, NULL, 0}, /* read counter */
		{"status", no_argument, NULL, 0}, /* status */
		{"read_data", no_argument, NULL, 0}, /* read data */
		{"write_data", no_argument, NULL, 0}, /* write data */
		{"write_key", no_argument, NULL, 0}, /* write key */
		{"read_cfg", no_argument, NULL, 0}, /* cfg_blk read */
		{"write_cfg", no_argument, NULL, 0}, /* cfg_blk write */
		{NULL, 0, NULL, 0}
	};
	static char *short_opts = "k:p:f:c:a:r:u:";

	while (-1 !=
	      (curr_opt = getopt_long(argc, argv, short_opts,
				      long_opts, &index))) {
		switch (curr_opt) {
		case 0:
			rt = check_op_type(long_opts[index].name, op, func);
			break;
		case 'k':
			rt = check_path(op->key_path, optarg);
			break;
		case 'p':
			rt = check_path(op->bsg_path, optarg);
			break;
		case 'f':
			rt = check_path(op->io_file, optarg);
			break;
		case 'c':
			rt = check_block_count(op);
			break;
		case 'a':
			rt = check_address(op);
			break;
		case 'r':
			rt = check_rpmb_region(op);
			break;
		case 'u':
			rt = check_lun(op);
			break;
		default:
			rt = -EINVAL;
			break;
		}
		if (rt)
			break;
	}

	return rt;
}

static int check_rpmb_opt(struct rpmb_opt *opt)
{
	int rt = OK;
	enum rpmb_type type = opt->type;

	if (type == INVALID) {
		print_error("Unknown operation type");
		exit(1);
	}

	if (opt->bsg_path[0] == '\0') {
		print_error("RPMB bsg device path is missing");
		rt = ERROR;
	}

	if (type == RPMB_READ_COUNTER || type == RPMB_PROGRAM_KEY ||
		type == RPMB_DATA_READ || type == RPMB_DATA_WRITE){
		if (opt->region == INVALID) {
			print_error("RPMB region number is missing");
			rt = ERROR;
		}
	}

	if (type == RPMB_PROGRAM_KEY || type == RPMB_DATA_WRITE ||
			type == RPMB_CFG_BLK_WRITE) {
		if (opt->key_path[0] == '\0') {
			print_error("RPMB region %d key path is missing",
					opt->region);
			rt = ERROR;
		}
	}

	if (type == RPMB_DATA_READ || type == RPMB_DATA_WRITE ||
			type == RPMB_CFG_BLK_WRITE ||
			type == RPMB_CFG_BLK_READ) {
		if (opt->io_file[0] == '\0') {
			print_error("input/output path is missing");
			rt = ERROR;
		}
		if (type != RPMB_CFG_BLK_READ &&
				opt->block_counts == INVALID) {
			/*
			 * As for the RPMB_CFG_BLK_READ,
			 * entry number is not required.
			 */
			print_error("block/entry count is missing");
			rt = ERROR;
		}
		if (type == RPMB_DATA_READ || type == RPMB_DATA_WRITE) {
			if (opt->addr == INVALID) {
				print_error("Address is missing");
				rt = ERROR;
			}
		}
		if (type == RPMB_CFG_BLK_WRITE ||
				type == RPMB_CFG_BLK_READ) {
			/*
			 * For Secure Write Protect Configuration Block access,
			 * the logical unit number is required.
			 */
			if (opt->lun == INVALID) {
				print_error("LUN is missing");
				rt = ERROR;
			}
		}
	}

	return rt;
}

static void init_rpmb_opt(struct rpmb_opt *opt)
{
	opt->key_path[0] = '\0';
	opt->bsg_path[0] = '\0';
	opt->io_file[0] = '\0';
	opt->addr = INVALID;
	opt->block_counts = INVALID;
	opt->region = INVALID;
	opt->lun = INVALID;
	opt->type = INVALID;
}

int do_rpmb(struct tool_options *opt)
{
	int rt = OK;
	struct rpmb_opt op;
	int (*func)(struct rpmb_opt *opt) = NULL;

	init_rpmb_opt(&op);

	rt = rpmb_parser(opt->cpy_of_argc, opt->cpy_of_argv, &op, &func);
	if (rt != OK) {
		print_error("Failed to parse rpmb command paramters");
		rpmb_help(opt->cpy_of_argv[0]);
		return rt;
	}

	rt = check_rpmb_opt(&op);
	if (!rt)
		rt = func(&op);

	return rt;
}

static char *help_str =
	"\nrpmb command usage:\n"
	"  %s rpmb [--status][--read_counter][--read_data][--write_data]\n"
	"	[--write_key][--read_cfg][--write_cfg][-k </path/to/key]\n"
	"	[-f output/input file>][-c <block/entry count>][-a <addr>]\n"
	"	[-r region][-p bsg]\n\n"
	"	--status       - Show RPMB LUN status, this version is just to read sense data.\n"
	"	--read_data    - Read [-c block count] data from RPMB LUN, and then save to\n"
	"			 output file specified by -f.\n"
	"	--write_data   - Write [-c block count] data from [-f input file] to RPMB LUN at\n"
	"			 address [-a <address>].\n"
	"	--write_key    - Program to key [-k key] to specified RPMB region\n"
	"	--read_counter - Read write counter from RPMB LUN to stdout\n"
	"	--read_cfg     - Secure Write Protect Configuration Block Read\n"
	"	--write_cfg    - Secure Write Protect Configuration Block Write\n"
	"	-k Specify the key file\n"
	"	-f Specify output/input file for the RPMB unit data read/write. For\n"
	"	   the Secure Write Protect Configuration Block access, it is used to\n"
	"	   specify configuration file.\n"
	"	-c Num. of 256 Bytes blocks for normal data read or wrote,\n"
	"	   Num. of Secure Write Protect Entry\n"
	"	-a Specify logical block address of data to be programmed to\n"
	"	   or read from specified RPMB region\n"
	"	-r Specify which RPMB region to access\n"
	"	-u Specify LUN to which secure write protection shall apply\n"
	"	-p Path to RPMB BSG device. Please note here is RPMB LUN BSG, not UFS BSG.\n\n"
	"  Note :\n"
	"	1. Regarding RPMB LUN BSG device, you can find it under /dev folder according\n"
	"	   to SAM 64-bit LUN. For example, UFS RPMB W-LUN is 0x44, and the first 8 bits\n"
	"	   of 64-bit SAM LUN is 0xC1, then get UFS RPMB SAM LUN is 0xC144000000000000.\n"
	"	   The device node in Linux system will be '0:0:0:49476'.\n"
	"	2. As for the format of the address inputted, hex number should be prefixed by 0x/0X\n"
	"	3. If you want to input key from standard input terminal, and output the data to\n"
	"	   standard output terminal, please use '-' as parameter of -k and -f when read data.\n"
	"	4. As for the Secure Write Protect Configuration Block read/write, its configuration\n"
	"	   file only contains enabled Secure Write Protect Entries raw data. That means it\n"
	"	   doesn't inlcude LUN, DATA LENGTH, and Reserved areas.\n"
	"  Eg :\n"
	"	1. Authentication Key Programming:\n"
	"	   %s rpmb --write_key -k /path/to/key -r 0 -p /path/to/rpmb/bsg\n"
	"	2. Read RPMB write counter, don't need verification with key:\n"
	"	   %s rpmb --read_counter -r 0 -p /path/to/rpmb/bsg\n"
	"	3. Read RPMB write counter, need verification with key, the key\n"
	"	   is read through standard input terminal:\n"
	"	   %s rpmb --read_counter -k - -r 0 -p /path/to/rpmb/bsg\n"
	"	4. Read Secure Write Protect Configuration Block from logical unit 1:\n"
	"	   %s rpmb --read_cfg -u 1 -f - -p /path/to/rpmb/bsg\n\n";
void rpmb_help(char *tool_name)
{
	printf(help_str, tool_name, tool_name, tool_name, tool_name, tool_name);
}
