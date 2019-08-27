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

#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))
#define DEBUG 1
static int read_rpmb_status(struct rpmb_opt *opt);
static int rpmb_read_counter(struct rpmb_opt *opt);
static int rpmb_program_key(struct rpmb_opt *opt);
static int rpmb_data_read(struct rpmb_opt *opt);
static int rpmb_data_write(struct rpmb_opt *opt);

static struct ufs_rpmb_type rpmb_op_t[] = {
	{"status", RPMB_STATUS, read_rpmb_status},
	{"read_counter", RPMB_READ_COUNTER, rpmb_read_counter},
	{"write_key", RPMB_PROGRAM_KEY, rpmb_program_key},
	{"read_data", RPMB_DATA_READ, rpmb_data_read},
	{"write_data", RPMB_DATA_WRITE, rpmb_data_write}
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

static void dump_buffer(const __u8 *buf, __u32 len)
{
	const __u8 *_buf = buf;
	__u32 i;

	for (i = 0; i < len; i++) {
		printf("0x%02x ", _buf[i]);
		if (!((i + 1) % 16))
			printf("\n");
	}
}

static const char *rpmb_result_str(__u32 result)
{
	switch (result) {
	case NO_ERROR:
		return "success";
	case GENERAL_FAILURE:
	case 0x81:
		return "General failure";
	case AUTH_FAILURE:
		return "Authentication failure";
	case COUNTER_FAILURE:
		return "Counter failure";
	case ADDR_FAILURE:
	case 0x84:
		return "Address failure";
	case WRITE_FAILURE:
		return "Write failure";
	case READ_FAILURE:
	case 0x86:
		return "Read failure";
	case KEY_NOT_PROGRAMMED:
		return "Authentication Key not yet programmed";
	case WT_PROT_CONFIG_FAILURE:
		return "SWPC block access failure";
	case INVALID_WT_PROT_CONFIG_PARA:
		return "Invalid SWPC parameter";
	case SEC_WT_PROT_NOT_APPLICABLE:
		return "Secure Write Protection not applicable";
	case 0x85:
		return "Write failure, write counter expired";
	default:
		return "Unknown result code";
	}
}

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
	int key_fd;
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
			return rt;
		key_size = st.st_size - 1; /* exclude EOF*/
		if (key_size <= 0 ||
		    key_size > RPMB_MSG_KEY_SIZE) {
			print_error("Invalid UFS RPMB key/MAC size %d",
				    key_size);
			return rt;
		}
	}

	rt = DO_IO(read, key_fd, key, RPMB_MSG_KEY_SIZE);
	if (rt < 0) {
		print_error("Read the key failed");
		return rt;
	} else if (rt != RPMB_MSG_KEY_SIZE) {
		print_error("Read %d bytes, auth key must be %lu bytes length",
			    rt,
			    RPMB_MSG_KEY_SIZE);
		return rt;
	}

	return OK;
}

static int execute_read_write(int bsg_fd, struct rpmb_mesg_frame *msg_in,
			      struct rpmb_mesg_frame *msg_out, __u32 cnt,
			      __u8 region, __u16 req_type)
{
	int rt = ERROR;
	__u16 expected_rsp;
	struct rpmb_mesg_frame rpmb_status = {0};
	__u16 sec_spec = (region << 8) | UFS_SECURITY_PROTOCOL_SPECIFIC;

	switch (req_type) {
	case RPMB_KEY_WRITE_REQ:
	case RPMB_WRITE_REQ:
		expected_rsp = (req_type == RPMB_KEY_WRITE_REQ) ?
			RPMB_KEY_PROG_RSP : RPMB_WRITE_RSP;
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
		expected_rsp = (req_type == RPMB_READ_REQ) ?
			RPMB_READ_RSP : RPMB_WC_READ_RSP;
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
		print_error("Unkonw RPMB request type");
		rt = -EINVAL;
		goto out;
	}
	if (be16toh(msg_out[cnt - 1].result) != 0x0000) {
		print_error("RPMB response got error result:%s",
			    rpmb_result_str(be16toh(msg_out[cnt - 1].result)));
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
		print_error("execute_read_write() failed while writing key");
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
		printf("RPMB LUN sense data:\n");
		dump_buffer(buf, 18);
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
		printf("Recived MAC:\n");
		dump_buffer(frames_out[cnt - 1].key_mac, RPMB_MSG_KEY_SIZE);
		printf("Expected MAC:\n");
		dump_buffer(mac, RPMB_MSG_KEY_SIZE);
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
		print_error("execute_read_write() failed while reading WC");
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
		print_error("execute_read_write() failed while reading data");
		goto out;
	}

	/*
	 * Read key, and verify data
	 */
	if (opt->key_path[0] != '\0') {
		rt = read_key(opt->key_path, key);
		if (rt) {
			print_error("Read key/MAC failed");
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
			print_error("can't open output file");
			goto out;
		}
	}
	int i;

	for (i = 0; i < blk_cnt; i++) {
		rt = DO_IO(write, out_fd, rpmb_msg_out[i].data,
			   RPMB_MSG_DATA_SIZE);
		if (rt < 0) {
			print_error("failed to output data");
			goto out;
		}
#ifdef DEBUG
		printf("\nData read from RPMB Region_%d,0x%08x:\n",
				region, (addr + i * RPMB_MSG_DATA_SIZE));
		dump_buffer(rpmb_msg_out[i].data, RPMB_MSG_DATA_SIZE);
#endif
	}

out:
	free(rpmb_msg_out);
	close(bsg_fd);
	if (out_fd != STDOUT_FILENO)
		close(out_fd);

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
		close(bsg_fd);
		return rt;
	}

	file_fd = open(opt->io_file, O_RDONLY);
	if (bsg_fd < 0) {
		print_error("Failed to open input file");
		close(bsg_fd);
		return rt;
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
		print_error("execute_read_write() failed while writing data");

out:
	close(bsg_fd);
	close(file_fd);
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
		{NULL, 0, NULL, 0}
	};
	static char *short_opts = "k:p:f:c:a:r:";

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

	if (type == RPMB_PROGRAM_KEY || type == RPMB_DATA_WRITE) {
		if (opt->key_path[0] == '\0') {
			print_error("RPMB region %d key path is missing",
					opt->region);
			rt = ERROR;
		}
	}

	if (type == RPMB_DATA_READ || type == RPMB_DATA_WRITE) {
		if (opt->io_file[0] == '\0') {
			print_error("input/output path is missing");
			rt = ERROR;
		}
		if (opt->block_counts == INVALID) {
			print_error("block count is missing");
			rt = ERROR;
		}
		if (opt->addr == INVALID) {
			print_error("Address is missing");
			rt = ERROR;
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
	"  %s rpmb [status][read-counter][read-data][write-data][write-key]\n"
	"	[-k </path/to/key][-f output/input file>][-c <block count>]\n"
	"	[-a <addr>][-p bsg]\n\n"
	"	--status       - Show RPMB LUN status\n"
	"	--read_data    - Read [-c block count] data from RPMB LUN, and\n"
	"		         then save to [-f <output file>]\n"
	"	--write_data   - Write [-c block count] data from [-f input file]\n"
	"		         to RPMB LUN at address [-a <address>]\n"
	"	--write_key    - Program key stored in [-k /path/to/key]\n"
	"	--read_counter - Read write-counter from RPMB LUN to stdout\n"
	"	-k specify the key file\n"
	"	-f specify the output or input file\n"
	"	-c specify Num. of 256 Bytes blocks will be read or wrote\n"
	"	-a specify the address to read/write\n"
	"	-r specify which RPMB region to access\n"
	"	-p Path to RPMB bsg device\n\n"
	"  Note :\n"
	"	1. As for the format of the address inputted, hex number\n"
	"	   should be prefixed by 0x/0X\n"
	"	2. If you want to input key from standard input terminal,\n"
	"	   and output the data to standard output terminal, please\n"
	"	   use - as parameter of -k and -f when read data\n"
	"  Eg :\n"
	"	1. Authentication Key Programming:\n"
	"	   %s rpmb --write_key -k /path/to/key -r 0 -p /path/to/rpmb/bsg\n"
	"	2. Read RPMB write counter, don't need verification with key:\n"
	"	   %s rpmb --read_counter -r 0 -p /path/to/rpmb/bsg\n"
	"	3. Read RPMB write counter, need verification with key. The key\n"
	"	   is read through standard input terminal:\n"
	"	   %s rpmb --read_counter -k - -r 0 -p /path/to/rpmb/bsg\n\n";
void rpmb_help(char *tool_name)
{
	printf(help_str, tool_name, tool_name, tool_name, tool_name);
}