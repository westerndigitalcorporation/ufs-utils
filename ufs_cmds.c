// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2018 Western Digital Corporation

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <ctype.h>
#include <errno.h>
#include <stdint.h>

#include "ufs.h"
#include "ufs_cmds.h"
#include "options.h"
#include "scsi_bsg_util.h"

#define ARRAYSIZE(x) (sizeof(x) / sizeof((x)[0]))

struct desc_field_offset device_config_desc_field_name[] = {
	{"bLength",		0x00, BYTE_SIZE},
	{"bDescriptorType",	0x01, BYTE_SIZE},
	{"bConfDescContinue",		0x02, BYTE_SIZE},
	{"bBootEnable",		0x03, BYTE_SIZE},
	{"bDescrAccessEn",	0x04, BYTE_SIZE},
	{"bInitPowerMode",	0x05, BYTE_SIZE},
	{"bHighPriorityLUN", 0x06, BYTE_SIZE},
	{"bSecureRemovalType",		0x07, BYTE_SIZE},
	{"bInitActiveICCLevel",		0x08, BYTE_SIZE},
	{"wPeriodicRTCUpdate",	0x09, (BYTE_SIZE<<1)},
	{"bRPMBRegionEnable", 0x0C, BYTE_SIZE},
	{"bRPMBRegion1Size", 0x0D, BYTE_SIZE},
	{"bRPMBRegion2Size", 0x0E, BYTE_SIZE},
	{"bRPMBRegion3Size", 0x0F, BYTE_SIZE},
};

enum acc_mode {
	READ_NORMAL = 1,
	READ_ONLY = (1 << 1),
	WRITE_ONLY = (1 << 2),
	WRITE_ONCE = (1 << 3),
	WRITE_PERSISTENT = (1 << 4),
	WRITE_VOLATILE = (1 << 5),
	SET_ONLY = (1 << 6),
	WRITE_POWER_ON_RESET = (1 << 7),
	ATTR_ACCESS_MODE_INVALID = (1 << 8)
};

enum attr_level {
	DEVICE = 1,
	ARRAY = (1 << 1),
	ATTR_LEVEL_INVALID = (1 << 2)
};

enum access_type {
	UREAD = 1,
	UWRITE = (1 << 1),
	UATTR_ACC_INVALID = (1 << 2)
};

struct attr_fields {
	char *name;
	enum field_width width_byte;
	enum access_type acc_type;
	enum acc_mode acc_mode;
	enum attr_level device_level;
};

struct flag_fields {
	char *name;
	enum access_type acc_type;
	enum acc_mode acc_mode;
	enum attr_level device_level;
	};

struct query_err_res {
	char *name;
	__u8 opcode;
};

struct attr_fields ufs_attrs[] = {
	/*0*/ {"bBootLunEn",                 BYTE_SIZE, (UREAD|UWRITE),
		(READ_ONLY|WRITE_PERSISTENT), DEVICE},
	/*1*/ {"Reserved",                    BYTE_SIZE, (UATTR_ACC_INVALID),
		ATTR_ACCESS_MODE_INVALID, ATTR_LEVEL_INVALID},
	/*2*/ {"bCurrentPowerMode",           BYTE_SIZE, (UREAD),
		READ_ONLY, DEVICE},
	/*3*/ {"bActiveICCLevel",            BYTE_SIZE, (UREAD|UWRITE),
		(READ_NORMAL | WRITE_PERSISTENT), DEVICE},
	/*4*/ {"bOutOfOrderDataEn",           BYTE_SIZE, (UREAD|UWRITE),
		(READ_NORMAL|WRITE_ONCE), DEVICE},
	/*5*/ {"bBackgroundOpStatus",         BYTE_SIZE, (UREAD),
		READ_ONLY, DEVICE},
	/*6*/ {"bPurgeStatus",                BYTE_SIZE, (UREAD),
		READ_ONLY, DEVICE},
	/*7*/ {"bMaxDataInSize",              BYTE_SIZE, (UREAD|UWRITE),
		(READ_NORMAL|WRITE_PERSISTENT), DEVICE},
	/*8*/ {"bMaxDataOutSize",             BYTE_SIZE, (UREAD|UWRITE),
		(READ_NORMAL|WRITE_PERSISTENT), DEVICE},
	/*9*/ {"dDynCapNeeded",               (BYTE_SIZE<<1), (UREAD),
		READ_ONLY, DEVICE},
	/*A*/ {"bRefClkFreq",                 BYTE_SIZE, (UREAD|UWRITE),
		(READ_NORMAL|WRITE_PERSISTENT), DEVICE},
	/*B*/ {"bConfigDescrLock",            BYTE_SIZE, (UREAD|UWRITE),
		(READ_NORMAL|WRITE_ONCE), DEVICE},
	/*C*/ {"bMaxNumOfRTT",                BYTE_SIZE, (UREAD|UWRITE),
		(READ_NORMAL|WRITE_PERSISTENT), DEVICE},
	/*D*/ {"wExceptionEventControl",      (BYTE_SIZE<<1), (UREAD),
		READ_NORMAL, DEVICE},
	/*E*/ {"wExceptionEventStatus",      (BYTE_SIZE<<1), (UREAD),
			READ_ONLY, DEVICE},
	/*F*/ {"dSecondsPassed",              (BYTE_SIZE<<2), (UWRITE),
		WRITE_ONLY, DEVICE},
	/*10*/ {"wContextConf",                (BYTE_SIZE<<1), (UREAD|UWRITE),
		(READ_NORMAL|WRITE_VOLATILE), ARRAY},
	/*11*/ {"Reserved",              BYTE_SIZE, (UATTR_ACC_INVALID),
			ATTR_ACCESS_MODE_INVALID, ATTR_LEVEL_INVALID},
	/*12*/ {"Reserved",                    BYTE_SIZE, (UATTR_ACC_INVALID),
			ATTR_ACCESS_MODE_INVALID, ATTR_LEVEL_INVALID},
	/*13*/ {"Reserved",                    BYTE_SIZE, (UATTR_ACC_INVALID),
			ATTR_ACCESS_MODE_INVALID, ATTR_LEVEL_INVALID},
	/*14*/ {"bDeviceFFUStatus",      BYTE_SIZE, (UREAD),
			READ_ONLY, DEVICE},
	/*15*/ {"bPSAState",                BYTE_SIZE, (UREAD|UWRITE),
			(READ_NORMAL|WRITE_PERSISTENT), DEVICE},
	/*16*/ {"dPSADataSize",      (BYTE_SIZE << 2), (UREAD|UWRITE),
			(READ_NORMAL|WRITE_PERSISTENT), DEVICE},
	/*17*/ {"bRefClkGatingWaitTime",    BYTE_SIZE, (UREAD),
			READ_ONLY, DEVICE},
	/*18*/ {"bDeviceCaseRoughTemperaure",      BYTE_SIZE, (UREAD),
			READ_ONLY, DEVICE},
	/*19*/ {"bDeviceTooHighTempBoundary",      BYTE_SIZE, (UREAD),
			READ_ONLY, DEVICE},
	/*1A*/ {"bDeviceTooLowTempBoundary",      BYTE_SIZE, (UREAD),
			READ_ONLY, DEVICE},
	/*1B*/ {"Reserved",                    BYTE_SIZE, (UATTR_ACC_INVALID),
			ATTR_ACCESS_MODE_INVALID, ATTR_LEVEL_INVALID},
	/*1C*/ {"Reserved",             BYTE_SIZE, (UATTR_ACC_INVALID),
			ATTR_ACCESS_MODE_INVALID, ATTR_LEVEL_INVALID},
	/*1D*/ {"Reserved",                    BYTE_SIZE, (UATTR_ACC_INVALID),
				ATTR_ACCESS_MODE_INVALID, ATTR_LEVEL_INVALID},
	/*1E*/ {"Reserved",                    BYTE_SIZE, (UATTR_ACC_INVALID),
			ATTR_ACCESS_MODE_INVALID, ATTR_LEVEL_INVALID},
	/*1F*/ {"Reserved",                    BYTE_SIZE, (UATTR_ACC_INVALID),
			ATTR_ACCESS_MODE_INVALID, ATTR_LEVEL_INVALID},
	/*20*/ {"Reserved",                    BYTE_SIZE, (UATTR_ACC_INVALID),
			ATTR_ACCESS_MODE_INVALID, ATTR_LEVEL_INVALID},
	/*21*/ {"Reserved",                    BYTE_SIZE, (UATTR_ACC_INVALID),
				ATTR_ACCESS_MODE_INVALID, ATTR_LEVEL_INVALID},
	/*22*/ {"Reserved",                    BYTE_SIZE, (UATTR_ACC_INVALID),
			ATTR_ACCESS_MODE_INVALID, ATTR_LEVEL_INVALID},
	/*23*/ {"Reserved",                    BYTE_SIZE, (UATTR_ACC_INVALID),
			ATTR_ACCESS_MODE_INVALID, ATTR_LEVEL_INVALID},
	/*24*/ {"Reserved",                    BYTE_SIZE, (UATTR_ACC_INVALID),
			ATTR_ACCESS_MODE_INVALID, ATTR_LEVEL_INVALID},
	/*25*/ {"Reserved",                    BYTE_SIZE, (UATTR_ACC_INVALID),
			ATTR_ACCESS_MODE_INVALID, ATTR_LEVEL_INVALID},
	/*26*/ {"Reserved",                    BYTE_SIZE, (UATTR_ACC_INVALID),
			ATTR_ACCESS_MODE_INVALID, ATTR_LEVEL_INVALID},
	/*27*/ {"Reserved",                    BYTE_SIZE, (UATTR_ACC_INVALID),
			ATTR_ACCESS_MODE_INVALID, ATTR_LEVEL_INVALID},
	/*28*/ {"Reserved",                    BYTE_SIZE, (UATTR_ACC_INVALID),
			ATTR_ACCESS_MODE_INVALID, ATTR_LEVEL_INVALID},
	/*29*/ {"Reserved",                    BYTE_SIZE, (UATTR_ACC_INVALID),
			ATTR_ACCESS_MODE_INVALID, ATTR_LEVEL_INVALID},
	/*2A*/ {"Reserved",                    BYTE_SIZE, (UATTR_ACC_INVALID),
			ATTR_ACCESS_MODE_INVALID, ATTR_LEVEL_INVALID},
	/*2B*/ {"Reserved",                    BYTE_SIZE, (UATTR_ACC_INVALID),
			ATTR_ACCESS_MODE_INVALID, ATTR_LEVEL_INVALID},
	/*2C*/ {"bRefreshStatus",      BYTE_SIZE, (UREAD),
			READ_ONLY, DEVICE},
	/*2D*/ {"bRefreshFreq",     BYTE_SIZE, (UREAD|UWRITE),
			(READ_NORMAL|WRITE_PERSISTENT), DEVICE},
	/*2E*/ {"bRefreshUnit",     BYTE_SIZE, (UREAD|UWRITE),
			(READ_NORMAL|WRITE_PERSISTENT), DEVICE},
	/*2F*/ {"bRefreshMethod",     BYTE_SIZE, (UREAD|UWRITE),
		(READ_NORMAL|WRITE_PERSISTENT), DEVICE}
};

struct flag_fields ufs_flags[] = {
	/*0*/ {"Reserved1", (UATTR_ACC_INVALID),
		(ATTR_ACCESS_MODE_INVALID), ATTR_LEVEL_INVALID},
	/*1*/ {"fDeviceInit", (UREAD|UWRITE),
		(READ_NORMAL|SET_ONLY), DEVICE},
	/*2*/ {"fPermanentWPEn", (UREAD|UWRITE),
		(READ_NORMAL|WRITE_ONCE), DEVICE},
	/*3*/ {"fPowerOnWPEn", (UREAD|UWRITE),
		(READ_NORMAL | WRITE_POWER_ON_RESET), DEVICE},
	/*4*/ {"fBackgroundOpsEn", (UREAD|UWRITE),
		(READ_NORMAL|WRITE_VOLATILE), DEVICE},
	/*5*/ {"fDeviceLifeSpanModeEn", (UREAD|UWRITE),
		(READ_NORMAL|WRITE_VOLATILE), DEVICE},
	/*6*/ {"fPurgeEnable", (UWRITE),
		(WRITE_ONLY | WRITE_VOLATILE), DEVICE},
	/*7*/ {"fRefreshEnable", (UWRITE),
		(WRITE_ONLY | WRITE_VOLATILE), DEVICE},
	/*8*/ {"fPhyResourceRemoval", (UREAD|UWRITE),
		(READ_NORMAL|WRITE_PERSISTENT), DEVICE},
	/*9*/ {"fBusyRTC", (UREAD),
		READ_ONLY, DEVICE},
	/*A*/{"Reserved3", (UATTR_ACC_INVALID),
		(ATTR_ACCESS_MODE_INVALID), ATTR_LEVEL_INVALID},
	/*B*/ {"fPermanentlyDisableFw", (UREAD|UWRITE),
		(READ_NORMAL | WRITE_ONCE), DEVICE},
};

static struct query_err_res query_err_status[] = {
		{"Success", 0xF0},
		{"Reserved1", 0xF1},
		{"Reserved2", 0xF2},
		{"Reserved3", 0xF3},
		{"Reserved4", 0xF4},
		{"Reserved5", 0xF5},
		{"Parameter not readable", 0xF6},
		{"Parameter not written", 0xF7},
		{"Parameter already written", 0xF8},
		{"Invalid LENGTH", 0xF9},
		{"Invalid value", 0xFA},
		{"Invalid SELECTOR", 0xFB},
		{"Invalid INDEX", 0xFC},
		{"Invalid IDN", 0xFD},
		{"Invalid OPCODE", 0xFE},
		{"General failure", 0xFF}
};

static int do_conf_desc(int fd, __u8 index, char *data_file);
static int do_string_desc(int fd, char *str_data, __u8 index);
static int do_query_rq(int fd, struct ufs_bsg_request *bsg_req,
	struct ufs_bsg_reply *bsg_rsp, __u8 query_req_func, __u8 opcode,
	__u8 idn, __u8 index, int len);
static void query_response_error(__u8 opcode, __u8 idn);

static char *access_type_string(__u8 current_att,
		__u8 config_type,
		char *access_string)
{
	enum acc_mode mode;

	switch (config_type) {
	case ATTR_TYPE:
		if (current_att >= QUERY_ATTR_IDN_MAX)
			return NULL;
		mode = ufs_attrs[current_att].acc_mode;
		break;
	case FLAG_TYPE:
		if (current_att >= QUERY_FLAG_IDN_MAX)
			return NULL;
		mode = ufs_flags[current_att].acc_mode;
		break;
	default:
		return NULL;
	}

	if (mode & READ_NORMAL)
		strcat(access_string, " | Read");
	if (mode & READ_ONLY)
		strcat(access_string, " | ReadOnly");
	if (mode & WRITE_ONLY)
		strcat(access_string, " | WriteOnly");
	if (mode & WRITE_ONCE)
		strcat(access_string, " | WriteOnce");
	if (mode & WRITE_PERSISTENT)
		strcat(access_string, " | Persistent");
	if (mode & WRITE_VOLATILE)
		strcat(access_string, " | Volatile");
	if (mode & SET_ONLY)
		strcat(access_string, " | SetOnly");
	if (mode & WRITE_POWER_ON_RESET)
		strcat(access_string, " | ResetOnPower");

	return access_string;
}

static void query_response_error(__u8 opcode, __u8 idn)
{
	__u8 query_response_inx = opcode & 0x0F;

	printf("\n %s, for idn 0x%02x\n",
		query_err_status[query_response_inx].name, idn);
}

void desc_help(char *tool_name)
{
	printf("\n Descriptor command usage:\n");
	printf("\n\t%s desc [-t] <descriptor idn> [-a|-r|-w] <data> [-p] "
		"<device_path> \n", tool_name);
	printf("\n\t-t\t description type idn\n"
			"\t\t Available description types based on UFS ver 3.0 :\n"
			"\t\t\t0:\tDevice\n"
			"\t\t\t1:\tConfiguration\n"
			"\t\t\t2:\tUnit\n"
			"\t\t\t3:\tRFU\n"
			"\t\t\t4:\tInterconnect\n"
			"\t\t\t5:\tString\n"
			"\t\t\t6:\tRFU\n"
			"\t\t\t7:\tGeometry\n"
			"\t\t\t8:\tPower\n"
			"\t\t\t9:\tDevice Health\n"
			"\t\t\t10..255: RFU\n");
	printf("\n\t-w\t write operation , for writable descriptors\n");
	printf("\t\t Set the input configuration file after -w opt\n");
	printf("\t\t for Configuration descriptor\n");
	printf("\t\t Set the input string after -w opt\n");
	printf("\t\t for String descriptor\n");
	printf("\n\t-i\t Set index parameter(default = 0)\n");
	printf("\n\t-p\t device path (LUN)\n");
}

void attribute_help(char *tool_name)
{
	__u8 current_att = 0;
	char access_string[100] = {0};

	printf("\n Attributes command usage:\n");
	printf("\n\t%s attr [-t] <attr_idn> [-a|-r|-w] <data_hex> [-p] "
		"<device_path> \n",
		tool_name);
	printf("\n\t-t\t Attributes type idn\n"
		"\t\t Available attributes and its access based on "
		"UFS ver 3.0 :\n");
	while (current_att < QUERY_ATTR_IDN_MAX) {
		printf("\t\t\t %-3d: %-25s %s\n",
			current_att,
			ufs_attrs[current_att].name,
			access_type_string(current_att, ATTR_TYPE,
			access_string));
		current_att++;
		memset(access_string, 0, 100);
	}

	printf("\n\t-a\tread and print all readable attributes for the device\n");
	printf("\n\t-r\tread operation (default), for readable attribute(s)\n");
	printf("\n\t-w\twrite operation (with hex data), "
		"for writable attribute\n");
	printf("\n\t-p\tdevice path (LUN)\n");
	printf("\n\tExample - Read bBootLunEn\n"
		"\t\t%s attr -t 0 -p /dev/ufs-bsg\n", tool_name);
}

void flag_help(char *tool_name)
{
	__u8 current_flag = 0;
	char access_string[100] = {0};

	printf("\n Flags command usage:\n");
	printf("\n\t%s fl [-t] <flag idn> [-a|-r|-s |-o|-e] [-p] <device_path>\n",
		tool_name);
	printf("\n\t-t\t Flags type idn\n"
		"\t\t Available flags and its access, based on UFS ver 3.0 :\n");

	while (current_flag < QUERY_FLAG_IDN_MAX) {
		printf("\t\t\t %-3d: %-25s %s\n",
			current_flag,
			ufs_flags[current_flag].name,
			access_type_string(current_flag, FLAG_TYPE,
				access_string));
		current_flag++;
		memset(access_string, 0, 100);
	}
	printf("\n\t-a\t read and print all readable flags for the device\n");
	printf("\n\t-r\t read operation (default), for readable flag(s)\n");
	printf("\n\t-e\t set flag operation\n");
	printf("\n\t-c\t clear/reset flag operation\n");
	printf("\n\t-o\t toggle flag operation\n");
	printf("\n\t-p\t device path (LUN)\n");
	printf("\n\tExample - Read the backops operation flag\n"
		"\t\t%s fl -t 4 -p /dev/ufs-bsg\n", tool_name);
}

static int do_string_desc(int fd, char *str_data, __u8 index)
{
	int rc = OK;
	__u8 desc_str[(sizeof(struct ufs_bsg_request)) + QUERY_DESC_STRING_MAX_SIZE] = {0};
	__u8 *desc_str_buffer = &(desc_str[(sizeof(struct ufs_bsg_request))]);
	struct ufs_bsg_request *bsg_req = (struct ufs_bsg_request *)&desc_str;
	struct ufs_bsg_reply bsg_rsp = {0};
	int len = strlen(str_data);

	strcpy((char *)desc_str_buffer, str_data);
	rc = do_query_rq(fd, bsg_req, &bsg_rsp,
		UPIU_QUERY_FUNC_STANDARD_WRITE_REQUEST,
		UPIU_QUERY_OPCODE_WRITE_DESC,
		QUERY_DESC_IDN_STRING, index, len);
	if (rc == OK)
		printf("\n String Descriptor was written \n");

	return rc;
}

static int do_conf_desc(int fd, __u8 index, char *data_file)
{
	int rc = OK;
	__u8 conf_desc[(sizeof(struct ufs_bsg_request)) +
		QUERY_DESC_CONFIGURAION_MAX_SIZE] = {0};
	__u8 *conf_desc_buffer =
			&(conf_desc[(sizeof(struct ufs_bsg_request))]);
	struct ufs_bsg_request *bsg_req = (struct ufs_bsg_request *)&conf_desc;
	struct ufs_bsg_reply bsg_rsp = {0};
	int data_fd;

	data_fd = open(data_file, O_RDONLY);
	if (data_fd < 0) {
		perror("can't open input file");
		return ERROR;
	}
	if (read(data_fd, conf_desc_buffer,
			QUERY_DESC_CONFIGURAION_MAX_SIZE) !=
			QUERY_DESC_CONFIGURAION_MAX_SIZE) {
		print_error("Could not read config data from  %s file",
			data_file);
		rc = ERROR;
		goto out;
	}
	rc = do_query_rq(fd, bsg_req, &bsg_rsp,
			UPIU_QUERY_FUNC_STANDARD_WRITE_REQUEST,
			UPIU_QUERY_OPCODE_WRITE_DESC,
			QUERY_DESC_IDN_CONFIGURAION, index,
			QUERY_DESC_CONFIGURAION_MAX_SIZE);
	if (!rc)
		printf("Config Descriptor was written to device\n");
out:
	close(data_fd);
	return rc;
}

int do_desc(struct tool_options *opt)
{
	int fd;
	int rc = OK;
	int oflag = O_RDWR;

	if (opt->opr == READ_ALL || opt->opr == READ)
		oflag = O_RDONLY;
	fd = open(opt->path, oflag);
	if (fd < 0) {
		perror("open");
		return ERROR;
	}

	switch (opt->idn) {
	case QUERY_DESC_IDN_CONFIGURAION:
		rc = do_conf_desc(fd, opt->index, (char *)opt->data);
		break;
	case QUERY_DESC_IDN_STRING:
		rc = do_string_desc(fd, (char *)opt->data, opt->index);
		break;
	default:
		print_error("Unsupported Descriptor type %d", opt->idn);
		break;
	}
	close(fd);
	return rc;
}

void print_attribute(struct attr_fields *attr, __u8 *attr_buffer)
{
	if (attr->width_byte == BYTE_SIZE)
		printf("%-26s := 0x%02x\n", attr->name, *(BYTE *)attr_buffer);
	else if (attr->width_byte == ((BYTE_SIZE << 1)))
		printf("%-26s := 0x%04x\n", attr->name, *(__u16 *)attr_buffer);
	else if (attr->width_byte == ((BYTE_SIZE << 2)))
		printf("%-26s := 0x%08x\n", attr->name,
			be32toh(*(__u32 *)attr_buffer));
}

static int do_query_rq(int fd,
	struct ufs_bsg_request *bsg_req,
	struct ufs_bsg_reply *bsg_rsp,
	__u8 query_req_func, __u8 opcode,
	__u8 idn, __u8 index, int len)
{
	int rc = OK;
	__u8 res_code;
	__u32 bsg_request_len = sizeof(struct ufs_bsg_request);
	__u32 bsg_rsp_len = sizeof(struct ufs_bsg_reply);

	prepare_upiu(bsg_req, query_req_func,
		len, opcode,
		idn, index);
	rc = send_bsg_sg_io(fd, bsg_req, bsg_rsp,
			bsg_request_len + len, bsg_rsp_len + len);

	if (rc) {
		print_error("%s: query failed, "
			"exception status %d idn = %d, index = %d",
			__func__, rc, idn, index);
		rc = ERROR;
	} else {
		res_code =
			(be32toh(*(__u32 *)&(bsg_rsp->upiu_rsp.header.dword_1)) >> 8) & 0xff;
		if (res_code) {
			query_response_error(res_code, idn);
			rc = ERROR;
		}
	}
	return rc;
}

int do_attributes(struct tool_options *opt)
{
	int fd;
	int rc = OK;
	struct attr_fields *tmp;
	int oflag = O_RDWR;
	__u8 att_idn;
	__u32 attr_value;
	struct ufs_bsg_request bsg_req = {0};
	struct ufs_bsg_reply bsg_rsp = {0};

	if (opt->opr == READ_ALL || opt->opr == READ)
		oflag = O_RDONLY;
	fd = open(opt->path, oflag);
	if (fd < 0) {
		perror("open");
		return ERROR;
	}

	if (opt->opr == READ_ALL) {
		att_idn = QUERY_ATTR_IDN_BOOT_LU_EN;

		while (att_idn < QUERY_ATTR_IDN_MAX) {
			tmp = &ufs_attrs[att_idn];
			if ((tmp->acc_type == UATTR_ACC_INVALID) ||
				(tmp->acc_type == UWRITE)) {
				att_idn++;
				continue;
			}
			rc = do_query_rq(fd, &bsg_req, &bsg_rsp,
				UPIU_QUERY_FUNC_STANDARD_READ_REQUEST,
				UPIU_QUERY_OPCODE_READ_ATTR,
				att_idn, 0, 0);
			if (rc == OK) {
				attr_value = be32toh(bsg_rsp.upiu_rsp.qr.value);
				print_attribute(&(ufs_attrs[att_idn]),
					(__u8 *)&attr_value);
			}
			memset(&bsg_rsp, 0, sizeof(struct ufs_bsg_reply));
			if (att_idn < QUERY_ATTR_IDN_MAX)
				++att_idn;
		}
	} else if (opt->opr == WRITE) {
		if ((ufs_attrs[opt->idn].acc_type == UATTR_ACC_INVALID) ||
			(ufs_attrs[opt->idn].acc_mode == READ_ONLY)) {
			print_error("%s Attribute is not writable",
				(ufs_flags[opt->idn]).name);
			rc = ERROR;
			goto out;
		}
		switch ((ufs_attrs[opt->idn]).width_byte) {
		case BYTE_SIZE:
			if (*(__u32 *)opt->data > 0xFF) {
				print_error("Wrong write data for %s attr\n",
					(ufs_attrs[opt->idn]).name);
				rc = ERROR;
				goto out;
			}
		break;
		case WORD_SIZE:
			if (*(__u32 *)opt->data > 0xFFFF) {
				print_error("Wrong write data for %s attr\n",
					(ufs_attrs[opt->idn]).name);
				rc = ERROR;
				goto out;
			}
		break;
		case DOUBLE_WORD_SIZE:
			if (*(__u32 *)opt->data > 0xFFFFFFFF) {
				print_error("Wrong write data for %s attr\n",
					(ufs_attrs[opt->idn]).name);
				rc = ERROR;
				goto out;
			}
		break;
		}
		bsg_req.upiu_req.qr.value = be32toh(*(__u32 *)opt->data);
		rc = do_query_rq(fd, &bsg_req, &bsg_rsp,
			UPIU_QUERY_FUNC_STANDARD_WRITE_REQUEST,
			UPIU_QUERY_OPCODE_WRITE_ATTR,
			opt->idn, 0, 0);
		if (rc == OK) {
			attr_value = be32toh(bsg_rsp.upiu_rsp.qr.value);
			print_attribute(&(ufs_attrs[opt->idn]),
				(__u8 *)&attr_value);
		}

	} else if (opt->opr == READ) {
		if ((ufs_attrs[opt->idn].acc_type == UATTR_ACC_INVALID)
			|| (ufs_attrs[opt->idn].acc_type == UWRITE)) {
			print_error("%s attribute is not readable",
				(ufs_attrs[opt->idn]).name);
			rc = ERROR;
		} else {
			rc = do_query_rq(fd, &bsg_req, &bsg_rsp,
				UPIU_QUERY_FUNC_STANDARD_READ_REQUEST,
				UPIU_QUERY_OPCODE_READ_ATTR,
				opt->idn, 0, 0);
			if (rc == OK) {
				attr_value = be32toh(bsg_rsp.upiu_rsp.qr.value);
				print_attribute(&(ufs_attrs[opt->idn]),
					(__u8 *)&attr_value);
			}
		}
	}
out:
	close(fd);
	return rc;
}

int do_flags(struct tool_options *opt)
{
	int fd;
	int rc = OK;
	__u8 current_flag;
	__u8 opcode, idn;
	struct flag_fields *tmp;
	struct ufs_bsg_request bsg_req = {0};
	struct ufs_bsg_reply bsg_rsp = {0};
	int oflag = O_RDWR;

	if (opt->opr == READ_ALL || opt->opr == READ)
		oflag = O_RDONLY;

	fd = open(opt->path, oflag);
	if (fd < 0) {
		perror("open");
		return ERROR;
	}

	switch (opt->opr) {
	case READ_ALL:
		current_flag = QUERY_FLAG_IDN_FDEVICEINIT;
		printf("UFS Device Flags:\n");
		while (current_flag < QUERY_FLAG_IDN_MAX) {
			tmp = &ufs_flags[current_flag];
			if ((tmp->acc_type == UATTR_ACC_INVALID) ||
				(tmp->acc_type == UWRITE)) {
				current_flag++;
				continue;
			}
			idn = current_flag;
			rc = do_query_rq(fd, &bsg_req, &bsg_rsp,
					UPIU_QUERY_FUNC_STANDARD_READ_REQUEST,
					UPIU_QUERY_OPCODE_READ_FLAG,
					idn, 0, 0);
			if (!rc)
				printf("%-26s := 0x%01x\n",
					(ufs_flags[idn]).name,
					be32toh(bsg_rsp.upiu_rsp.qr.value)&0xff);
			memset(&bsg_rsp, 0, sizeof(struct ufs_bsg_reply));
			if (current_flag < QUERY_FLAG_IDN_MAX)
				++current_flag;
		}
	break;
	case CLEAR_FLAG:
	case TOGGLE_FLAG:
	case SET_FLAG:
		if ((ufs_flags[opt->idn].acc_type == UATTR_ACC_INVALID) ||
			(ufs_flags[opt->idn].acc_mode == READ_ONLY)) {
			print_error("%s flag is not writable",
				(ufs_flags[opt->idn]).name);
			rc = ERROR;
		} else if ((ufs_flags[opt->idn].acc_mode & SET_ONLY) &&
				(opt->opr != SET_FLAG)) {
			print_error("Only set operation supported for %s flag",
				(ufs_flags[opt->idn]).name);
			rc = ERROR;
		} else {
			if (opt->opr == CLEAR_FLAG)
				opcode = UPIU_QUERY_OPCODE_CLEAR_FLAG;
			else if (opt->opr == SET_FLAG)
				opcode = UPIU_QUERY_OPCODE_SET_FLAG;
			else if (opt->opr == TOGGLE_FLAG)
				opcode = UPIU_QUERY_OPCODE_TOGGLE_FLAG;
			rc = do_query_rq(fd, &bsg_req, &bsg_rsp,
					UPIU_QUERY_FUNC_STANDARD_WRITE_REQUEST,
					opcode,
					opt->idn, 0, 0);
			if (!rc)
				printf("%-26s := 0x%01x\n",
					(ufs_flags[opt->idn]).name,
					be32toh(bsg_rsp.upiu_rsp.qr.value)&0xff);
		}
	break;
	case READ:/*Read operation */
		if ((ufs_flags[opt->idn].acc_type == UATTR_ACC_INVALID) ||
			(ufs_flags[opt->idn].acc_type == UWRITE)) {
			print_error("%s flag is not readable",
				(ufs_flags[opt->idn]).name);
			rc = ERROR;
		} else {
			rc = do_query_rq(fd, &bsg_req, &bsg_rsp,
					UPIU_QUERY_FUNC_STANDARD_READ_REQUEST,
					UPIU_QUERY_OPCODE_READ_FLAG,
					opt->idn, 0, 0);
			if (!rc)
				printf("%-26s := 0x%01x\n",
					(ufs_flags[opt->idn]).name,
					be32toh(bsg_rsp.upiu_rsp.qr.value)&0xff);
		}

	break;
	default:
		print_error("Unsupported operation for %s flag",
			(ufs_flags[opt->idn]).name);
		rc = ERROR;
	break;
	}

	close(fd);
	return rc;
}

void print_command_help(char *prgname, int config_type)
{
	switch (config_type) {
	case DESC_TYPE:
		desc_help(prgname);
		break;
	case ATTR_TYPE:
		attribute_help(prgname);
		break;
	case FLAG_TYPE:
		flag_help(prgname);
		break;
	default:
		print_error("Unsupported cmd type");
		break;
	}
}
