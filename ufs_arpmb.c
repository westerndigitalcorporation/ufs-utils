// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Most of the source code refers to ufs_rpmb.c,
 * And changed and updated by:
 *	Bean Huo <beanhuo@micron.com>
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <dirent.h>
#include <endian.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdint.h>
#include <errno.h>
#include <stdbool.h>
#include "ufs.h"
#include "ufs_cmds.h"
#include "options.h"
#include "ufs_rpmb.h"
#include "hmac_sha2.h"
#include "scsi_bsg_util.h"

static unsigned char key_buff[RPMB_KEY_SIZE];

extern int do_read_desc(int fd, struct ufs_bsg_request *bsg_req, struct ufs_bsg_reply *bsg_rsp,
			__u8 idn, __u8 index, __u16 desc_buf_len, __u8 *data_buf);

static int arpmb_calc_hmac_sha256(struct ufs_ehs *ehs, __u8 *data, size_t len,
				  const unsigned char key[], __u32 key_size,
				  unsigned char mac[], __u32 mac_size)
{
	hmac_sha256_ctx ctx;
	char padding[4];

	hmac_sha256_init(&ctx, key, key_size);

	/*
	 * If RPMB Message includes data in a DATA IN UPIU or a DATA OUT UPIU, the concatenation
	 * of the data transferred in each DATA IN/OUT UPIU in the order in which it is sent is
	 * input into the MAC calculation. Then the concatenation of the fields in the Advanced
	 * RPMB Meta Information from byte 0 to byte 27 is input into the MAC calculation. After
	 * this, four 00h bytes are input into the MAC calculation.
	 */
	hmac_sha256_update(&ctx, CUC(data), len);
	hmac_sha256_update(&ctx, CUC(ehs->meta_bytes), 28);
	hmac_sha256_update(&ctx, CUC(padding), 4);

	hmac_sha256_final(&ctx, mac, mac_size);

	return 0;
}


static int do_arpmb_op(int ufs_bsg_fd, struct ufs_rpmb_request *ufs_arpmb_req,
		       struct ufs_rpmb_reply *ufs_arpmb_resp,
		       __u8 region, __u32 len, __u8 *data, enum rpmb_op_type op)
{
	__u8 cdb[SEC_PROTOCOL_CMD_SIZE] = {0};
	bool write =  false;
	int ret = -EINVAL;
	__u8 opcode;
	__u8 flags;

	if (!ufs_arpmb_req || !ufs_arpmb_resp) {
		print_error("Wrong arpmb parameters");
		goto out;
	}

	switch (op) {
	case RPMB_WRITE_KEY:
		opcode = SECURITY_PROTOCOL_OUT;
		write = true;
		flags = 0x20;
		break;
	case RPMB_READ_CNT:
		opcode = SECURITY_PROTOCOL_IN;
		flags = 0x40;
		break;
	case RPMB_READ:
		opcode = SECURITY_PROTOCOL_IN;
		flags = 0x40;
		break;
	case RPMB_WRITE:
		opcode = SECURITY_PROTOCOL_OUT;
		write = true;
		flags = 0x20;
		break;
	default:
		return -EINVAL;
	}

	prepare_security_cdb(cdb, len, region, opcode);
	prepare_command_upiu(&ufs_arpmb_req->bsg_request.upiu_req, flags, 0xC4, 2, cdb,
				SEC_PROTOCOL_CMD_SIZE, len);

	ufs_arpmb_req->bsg_request.msgcode = UPIU_TRANSACTION_ARPMB_CMD;

	ret = send_bsg_scsi_trs(ufs_bsg_fd, ufs_arpmb_req, ufs_arpmb_resp,
			       sizeof(struct ufs_rpmb_request), sizeof(struct ufs_rpmb_reply),
			       len, data, write);
	if (!ret) {

		if (be32toh(ufs_arpmb_resp->bsg_reply.upiu_rsp.header.dword_1) & 0xFFFF) {
			print_error("ARPMB CMD failed, with response in UPIU 0x%x, status 0x%x.\n",
			(be32toh(ufs_arpmb_resp->bsg_reply.upiu_rsp.header.dword_1) & 0xFF00) >> 8,
			be32toh(ufs_arpmb_resp->bsg_reply.upiu_rsp.header.dword_1) & 0xFF);

			ret  = -EINVAL;
		} else if (ufs_arpmb_resp->bsg_reply.result) {
			print_error("ARPMB OP failed %d :%d\n", ret,
					ufs_arpmb_resp->bsg_reply.result);

			ret = ret ? : ufs_arpmb_resp->bsg_reply.result;
		}
	}

out:
	return ret;
}

static int do_arpmb_key(int ufs_bsg_fd, const unsigned char *key, __u8 region)
{
	struct ufs_rpmb_request ufs_arpmb_req = { 0 };
	struct ufs_rpmb_reply ufs_arpmb_resp = { 0 };
	int ret = INVALID;

	if (key == NULL) {
		WRITE_LOG0("key is NULL");
		goto out;
	}

	ufs_arpmb_req.ehs_req.blenght = 0x02;
	ufs_arpmb_req.ehs_req.lehs_type = 0x01;
	ufs_arpmb_req.ehs_req.meta.req_resp_type = htobe16(RPMB_WRITE_KEY);

	memcpy(ufs_arpmb_req.ehs_req.mac_key, key, sizeof(ufs_arpmb_req.ehs_req.mac_key));
	WRITE_LOG("Start : %s\n", __func__);
	ret = do_arpmb_op(ufs_bsg_fd, &ufs_arpmb_req, &ufs_arpmb_resp, region, 0, NULL,
			  RPMB_WRITE_KEY);

	if (!ret) {
		if (ufs_arpmb_resp.ehs_rsp.meta.result != 0) {
			print_operation_error(be16toh(ufs_arpmb_resp.ehs_rsp.meta.result));
			goto out;
		} else {
			printf("ARPMB key is programmed\n");
		}
	}
out:
	return ret;
}

static int do_arpmb_read_counter(int fd, __u32 *cnt, __u8 region, __u8 sg_type, bool prn_cnt)
{
	struct ufs_rpmb_request ufs_arpmb_req = { 0 };
	struct ufs_rpmb_reply ufs_arpmb_resp = { 0 };
	int ret;

	WRITE_LOG("Start : %s %d\n", __func__, region);

	ufs_arpmb_req.ehs_req.blenght = 0x02;
	ufs_arpmb_req.ehs_req.lehs_type = 0x01;
	ufs_arpmb_req.ehs_req.meta.req_resp_type = htobe16(RPMB_READ_CNT);

	ret = do_arpmb_op(fd, &ufs_arpmb_req, &ufs_arpmb_resp, region, 0, 0, RPMB_READ_CNT);

	if (!ret) {
		if (ufs_arpmb_resp.ehs_rsp.meta.result != 0) {
			print_operation_error(be16toh(ufs_arpmb_resp.ehs_rsp.meta.result));
		} else {
			if (prn_cnt)
				printf("ARPMB write counter = %u\n",
					be32toh(ufs_arpmb_resp.ehs_rsp.meta.write_counter));
			*cnt = be32toh(ufs_arpmb_resp.ehs_rsp.meta.write_counter);
		}
	}

	return ret;
}

static int do_read_arpmb(int fd, int out_fd, unsigned char *key, int start_addr,
			int num_blocks, __u8 region)
{
	struct ufs_bsg_request bsg_req = { 0 };
	struct ufs_bsg_reply bsg_rsp = { 0 };
	int ret = ERROR;
	ssize_t write_size;
	__u8 max_num_blocks;
	__u8 num_read_blocks = 0;
	__u8 *buff = NULL;

	struct ufs_rpmb_request ufs_arpmb_req = { 0 };
	struct ufs_rpmb_reply ufs_arpmb_rsp = { 0 };
	__u8 data_buf[QUERY_DESC_GEOMETRY_MAX_SIZE] = { 0 };

	WRITE_LOG("Start : %s , address %d , num_blocks %d\n", __func__, start_addr, num_blocks);

	ret = do_read_desc(fd, &bsg_req, &bsg_rsp, QUERY_DESC_IDN_GEOMETRY, 0,
				QUERY_DESC_GEOMETRY_MAX_SIZE, data_buf);

	if (ret) {
		/* Could not read geometry descriptor, max block set DEFAULT_RPMB_NUM_BLOCKS */
		print_warn("Cannot get bRPMB_ReadWriteSize");
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
		if (start_addr > ARPMB_MAX_ADDRESS) {
			print_error("Max available address is reached");
			goto out;
		}

		buff = calloc(num_read_blocks, 4096);
		if (!buff) {
			print_error("Cannot allocate %d RPMB frames",
					num_blocks);
			goto out;
		}

		ufs_arpmb_req.ehs_req.blenght = 0x02;
		ufs_arpmb_req.ehs_req.lehs_type = 0x01;
		ufs_arpmb_req.ehs_req.meta.req_resp_type = htobe16(RPMB_READ);
		ufs_arpmb_req.ehs_req.meta.addr = htobe16(start_addr);
		ufs_arpmb_req.ehs_req.meta.block_count = htobe16(num_read_blocks);
		ret = do_arpmb_op(fd, &ufs_arpmb_req, &ufs_arpmb_rsp, region,
				  num_read_blocks * 4096, buff, RPMB_READ);
		if (ret != 0) {
			print_error("ARPMB operation is failed in addr %d ", start_addr);
			goto out;
		}
		if (ufs_arpmb_rsp.ehs_rsp.meta.result != 0) {
			print_operation_error(be16toh(ufs_arpmb_rsp.ehs_rsp.meta.result));
			ret = -EINVAL;
			goto out;
		}

		/* In case an user get the key, verify the hash */
		if (key != NULL) {
			__u8 mac[RPMB_MAC_SIZE];

			arpmb_calc_hmac_sha256(&ufs_arpmb_rsp.ehs_rsp, buff, num_read_blocks * 4096,
					      key, RPMB_KEY_SIZE, mac, RPMB_MAC_SIZE);
			/*
			 * Compare calculated MAC and MAC from last frame
			 * Note the mac much only in case we read 1 block ,
			 * otherwise the mac field is not much, in all frame ,
			 * include the last one
			 */
			if (memcmp(mac, ufs_arpmb_rsp.ehs_rsp.mac_key, sizeof(mac)))
				print_warn("ARPMB MAC mismatch mac");
		}


		write_size = write(out_fd, buff, num_read_blocks * 4096);
		if (write_size  !=  num_read_blocks * 4096) {
			printf("%s: failed in write sz=%d errno=%d\n", __func__,
				(int)write_size, errno);
			ret = INVALID;
			goto out;
		}

		WRITE_LOG("num_blocks : %d start_addr %d num_read_blocks %d\n", num_blocks,
				start_addr, num_read_blocks);
		num_blocks = num_blocks - num_read_blocks;
		start_addr = start_addr + num_read_blocks;

		if (num_blocks > max_num_blocks)
			num_read_blocks = max_num_blocks;
		else
			num_read_blocks = num_blocks;

		if (buff) {
			free(buff);
			buff = NULL;
		}
	}
out:
	if (buff)
		free(buff);

	return ret;
}

static int do_write_arpmb(int fd, const unsigned char *key, int input_fd, __u32 cnt,
			int start_addr, int num_blocks, __u8 region, __u8 sg_type)
{
	struct ufs_bsg_request bsg_req = { 0 };
	struct ufs_bsg_reply bsg_rsp = { 0 };
	unsigned char mac[RPMB_MAC_SIZE];
	int ret = ERROR;
	__u8 *buff;
	__u8 max_num_blocks;
	ssize_t read_size = 0;
	__u8 num_write_blocks = 0;
	int j = 0;

	struct ufs_rpmb_request ufs_arpmb_req = { 0 };
	struct ufs_rpmb_reply ufs_arpmb_rsp = { 0 };
	__u8 data_buf[QUERY_DESC_GEOMETRY_MAX_SIZE] = { 0 };

	WRITE_LOG("Start : %s\n", __func__);

	ret = do_read_desc(fd, &bsg_req, &bsg_rsp, QUERY_DESC_IDN_GEOMETRY, 0,
				QUERY_DESC_GEOMETRY_MAX_SIZE, data_buf);

	if (ret) {
		print_warn("Cannot get bRPMB_ReadWriteSize");
		max_num_blocks = DEFAULT_RPMB_NUM_BLOCKS;
	} else {
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
		if (start_addr > ARPMB_MAX_ADDRESS) {
			print_error("Max available address is reached");
			goto out;
		}

		buff = calloc(num_write_blocks, 4096);
		if (!buff) {
			print_error("Cannot allocate %d RPMB frames", num_blocks);
			ret = -ENOMEM;
			goto out;
		}

		read_size = read(input_fd, buff, num_write_blocks * 4096);
		if (read_size != num_write_blocks * 4096) {

			WRITE_LOG("%s: failed in read size=%d errno=%d",
				  __func__, (int)read_size, errno);
			ret = -EINVAL;
			goto out;
		}

		ufs_arpmb_req.ehs_req.blenght = 0x02;
		ufs_arpmb_req.ehs_req.lehs_type = 0x01;
		ufs_arpmb_req.ehs_req.meta.req_resp_type = htobe16(RPMB_WRITE);
		ufs_arpmb_req.ehs_req.meta.addr = htobe16(start_addr);
		ufs_arpmb_req.ehs_req.meta.block_count =   htobe16(num_write_blocks);
		ufs_arpmb_req.ehs_req.meta.write_counter = htobe32(cnt);

		arpmb_calc_hmac_sha256(&ufs_arpmb_req.ehs_req, buff, read_size,
				       key, RPMB_KEY_SIZE, mac, RPMB_MAC_SIZE);

		memcpy(ufs_arpmb_req.ehs_req.mac_key, mac, RPMB_MAC_SIZE);

		ret = do_arpmb_op(fd, &ufs_arpmb_req, &ufs_arpmb_rsp,
				  region, num_write_blocks * 4096, buff, RPMB_WRITE);
		if (ret != 0)
			goto out;

		/* Check RPMB response */
		if (ufs_arpmb_rsp.ehs_rsp.meta.result != 0) {
			print_operation_error(be16toh(ufs_arpmb_rsp.ehs_rsp.meta.result));
			ret = -EINVAL;
			goto out;
		}

		WRITE_LOG("num_blocks : %d start_addr %d num_write_blocks %d ,iter %d,cnt %d\n",
			  num_blocks, start_addr, num_write_blocks, j, cnt);

		num_blocks = num_blocks - num_write_blocks;
		start_addr = start_addr + num_write_blocks;
		if (num_blocks > max_num_blocks)
			num_write_blocks = max_num_blocks;
		else
			num_write_blocks = num_blocks;
		j++;
		cnt++;
		if (buff) {
			free(buff);
			buff = NULL;
		}

	}
out:
	if (buff)
		free(buff);
	return ret;
}

int do_arpmb(struct tool_options *opt)
{
	unsigned char *key_ptr = NULL;
	int output_fd = INVALID;
	int rc = INVALID;
	int fd;
	__u32 cnt = 0;

	fd = open(opt->path, O_RDWR | O_SYNC);
	if (fd < 0) {
		perror("open");
		return ERROR;
	}

	switch (opt->idn) {
	case AUTHENTICATION_KEY:
		key_ptr = get_auth_key(opt->keypath, key_buff);
		if (key_ptr == NULL)
			goto out;
		rc = do_arpmb_key(fd, key_ptr, opt->region);
		break;
	case READ_WRITE_COUNTER:
		rc = do_arpmb_read_counter(fd, &cnt, opt->region, opt->sg_type, true);
		break;
	case READ_RPMB:
		output_fd = open(opt->data, O_WRONLY | O_CREAT | O_SYNC, S_IRUSR | S_IWUSR);
		if (output_fd < 0) {
			perror("Output file open");
			goto out;
		}

		if (opt->keypath[0] != 0) {
			key_ptr = get_auth_key(opt->keypath, key_buff);
			if (key_ptr == NULL)
				goto out;
		}

		rc = do_read_arpmb(fd, output_fd, key_ptr, opt->start_block, opt->num_block,
					opt->region);
		if (!rc)
			printf("Finish to read ARPMB data\n");
		break;
	case WRITE_RPMB:
		key_ptr = get_auth_key(opt->keypath, key_buff);
		if (key_ptr == NULL)
			goto out;

		output_fd = open(opt->data, O_RDONLY | O_SYNC);
		if (output_fd < 0) {
			perror("Input file open");
			goto out;
		}

		rc = do_arpmb_read_counter(fd, &cnt, opt->region, opt->sg_type, false);
		if (rc)
			goto out;

		rc = do_write_arpmb(fd, key_ptr, output_fd, cnt, opt->start_block, opt->num_block,
				opt->region, opt->sg_type);
		if (!rc)
			printf("Finish to write ARPMB data\n");
		break;
	default:
		print_error("Unsupported ARPMB cmd %d", opt->idn);
		break;
	}
out:
	if (output_fd != INVALID)
		close(output_fd);
	close(fd);

	return rc;
}

void arpmb_help(char *tool_name)
{
	printf("\n Advanced RPMB command usage:\n");
	printf("\n\t%s arpmb [-t] <rpmb cmd idn> [-p] <UFS BSG device>"
		" -k <path to key_file> -n <block_count> -w <output/input file>.\n", tool_name);
	printf("\n\t-t\t RPMB cmd type idn in advanced RPMB mode\n"
		"\t\t\t0:\tKey provision\n"
		"\t\t\t1:\tRead Write counter\n"
		"\t\t\t2:\tRead RPMB data\n"
		"\t\t\t3:\tWrite RPMB data\n");

	printf("\n\t-s\t RPMB start address (default value is 0)\n");
	printf("\n\t-n\t RPMB read/write blocks (default value is 1, the block size is 4KB)\n");
	printf("\n\t-p\t ufs_bsg device path\n");
	printf("\n\t-k\t path to RPMB key file\n");
	printf("\n\t-w\t path to data file for read/write\n");
	printf("\n\t-m\t RPMB region.\n");

	printf("\n\tExample 1 - Read 8KB of data from RPMB LUN started "
		"from address 0 to output file\n"
		"\t\t  %s arpmb -t 2 -p /dev/bsg/ufs_bsg0 -s 0 -n 2 -w output_file\n", tool_name);
	printf("\n\tExample 2 - Write RPMB key\n"
		"\t\t  %s arpmb -t 0 -p /dev/bsg/ufs_bsg0 -k key_file\n", tool_name);
	printf("\n\tExample 3 - Write RPMB key to region 2\n"
		"\t\t  %s arpmb -t 0 -m 2 -p /dev/bsg/ufs_bsg0 -k key_file\n", tool_name);
}
