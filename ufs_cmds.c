// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2019 Western Digital Corporation or its affiliates */

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
#include "ufs_err_hist.h"
#include "unipro.h"
#include "ufs_ffu.h"

#define STR_BUF_LEN 33
#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))
#define ATTR_RSRV() "Reserved", BYTE, ACC_INVALID, MODE_INVALID, LEVEL_INVALID

struct desc_field_offset device_desc_field_name[] = {
	{"bLength",			0x00, BYTE},
	{"bDescriptorType",		0x01, BYTE},
	{"bDevice",			0x02, BYTE},
	{"bDeviceClass",		0x03, BYTE},
	{"bDeviceSubClass",		0x04, BYTE},
	{"bProtocol",			0x05, BYTE},
	{"bNumberLU",			0x06, BYTE},
	{"bNumberWLU",			0x07, BYTE},
	{"bBootEnable",			0x08, BYTE},
	{"bDescrAccessEn",		0x09, BYTE},
	{"bInitPowerMode",		0x0A, BYTE},
	{"bHighPriorityLUN",		0x0B, BYTE},
	{"bSecureRemovalType",		0x0C, BYTE},
	{"bSecurityLU",			0x0D, BYTE},
	{"bBackgroundOpsTermLat",	0x0E, BYTE},
	{"bInitActiveICCLevel",		0x0F, BYTE},
	{"wSpecVersion",		0x10, WORD},
	{"wManufactureDate",		0x12, WORD},
	{"iManufactureName",		0x14, BYTE},
	{"iProductName",		0x15, BYTE},
	{"iSerialNumber",		0x16, BYTE},
	{"iOemID",			0x17, BYTE},
	{"ManufacturerID",		0x18, WORD},
	{"bUD0BaseOffset",		0x1A, BYTE},
	{"bUDConfigPLength",		0x1B, BYTE},
	{"bDeviceRTTCap",		0x1C, BYTE},
	{"wPeriodicRTCUpdate",		0x1D, WORD},
	{"bUFSFeaturesSupport",		0x1F, BYTE},
	{"bFFUTimeout",			0x20, BYTE},
	{"bQueueDepth",			0x21, BYTE},
	{"wDeviceVersion",		0x22, WORD},
	{"bNumSecureWPArea",		0x24, BYTE},
	{"dPSAMaxDataSize",		0x25, DWORD},
	{"bPSAStateTimeout",		0x29, BYTE},
	{"iProductRevisionLevel",	0x2A, BYTE}
};

struct desc_field_offset device_config_desc_field_name[] = {
	{"bLength",		0x00, BYTE},
	{"bDescriptorType",	0x01, BYTE},
	{"bConfDescContinue",	0x02, BYTE},
	{"bBootEnable",		0x03, BYTE},
	{"bDescrAccessEn",	0x04, BYTE},
	{"bInitPowerMode",	0x05, BYTE},
	{"bHighPriorityLUN",	0x06, BYTE},
	{"bSecureRemovalType",	0x07, BYTE},
	{"bInitActiveICCLevel",	0x08, BYTE},
	{"wPeriodicRTCUpdate",	0x09, WORD},
	{"bRPMBRegionEnable",	0x0C, BYTE},
	{"bRPMBRegion1Size",	0x0D, BYTE},
	{"bRPMBRegion2Size",	0x0E, BYTE},
	{"bRPMBRegion3Size",	0x0F, BYTE},
};

struct desc_field_offset device_config_unit_desc_field_name[] = {
	{"bLUEnable",			0x00, BYTE},
	{"bBootLunID",			0x01, BYTE},
	{"bLUWriteProtect",		0x02, BYTE},
	{"bMemoryType",			0x03, BYTE},
	{"dNumAllocUnits",		0x04, DWORD},
	{"bDataReliability",		0x08, BYTE},
	{"bLogicalBlockSize",		0x09, BYTE},
	{"bProvisioningType",		0x0A, BYTE},
	{"wContextCapabilities",	0x0B, WORD}
};

struct desc_field_offset device_geo_desc_conf_field_name[] = {
	{"bLength",				0x00, BYTE},
	{"bDescriptorType ",			0x01, BYTE},
	{"bMediaTechnology",			0x02, BYTE},
	{"qTotalRawDeviceCapacity",		0x04, DDWORD},
	{"bMaxNumberLU",			0x0C, DWORD},
	{"dSegmentSize",			0x0D, DWORD},
	{"bAllocationUnitSize",			0x11, BYTE},
	{"bMinAddrBlockSize",			0x12, BYTE},
	{"bOptimalReadBlockSize",		0x13, BYTE},
	{"bOptimalWriteBlockSize",		0x14, BYTE},
	{"bMaxInBufferSize",			0x15, BYTE},
	{"bMaxOutBufferSize",			0x16, BYTE},
	{"bRPMB_ReadWriteSize",			0x17, BYTE},
	{"bDynamicCapacityResourcePolicy",	0x18, BYTE},
	{"bDataOrdering",			0x19, BYTE},
	{"bMaxContexIDNumber",			0x1A, BYTE},
	{"bSysDataTagUnitSize",			0x1B, BYTE},
	{"bSysDataTagResSize",			0x1C, BYTE},
	{"bSupportedSecRTypes",			0x1D, BYTE},
	{"wSupportedMemoryTypes",		0x1E, WORD},
	{"dSystemCodeMaxNAllocU",		0x20, DWORD},
	{"wSystemCodeCapAdjFac",		0x24, DWORD},
	{"dNonPersistMaxNAllocU",		0x26, DWORD},
	{"wNonPersistCapAdjFac",		0x2A, WORD},
	{"dEnhanced1MaxNAllocU",		0x2C, DWORD},
	{"wEnhanced1CapAdjFac",			0x30, WORD},
	{"dEnhanced2MaxNAllocU",		0x32, DWORD},
	{"wEnhanced2CapAdjFac",			0x36, WORD},
	{"dEnhanced3MaxNAllocU",		0x38, DWORD},
	{"wEnhanced3CapAdjFac",			0x3C, WORD},
	{"dEnhanced4MaxNAllocU",		0x3E, DWORD},
	{"wEnhanced4CapAdjFac",			0X42, WORD},
	{"dOptimalLogicalBlockSize",		0X44, DWORD}
};

struct desc_field_offset device_interconnect_desc_conf_field_name[] = {
	{"bLength",		0x00, BYTE},
	{"bDescriptorType",	0x01, BYTE},
	{"bcdUniproVersion",	0x02, WORD},
	{"bcdMphyVersion ",	0x04, WORD},
};

struct desc_field_offset device_unit_desc_field_name[] = {
	{"bLength",			0x00, BYTE},
	{"bDescriptorType",		0x01, BYTE},
	{"bUnitIndex",			0x02, BYTE},
	{"bLUEnable",			0x03, BYTE},
	{"bBootLunID",			0x04, BYTE},
	{"bLUWriteProtect",		0x05, BYTE},
	{"bLUQueueDepth",		0x06, BYTE},
	{"bPSASensitive",		0x07, BYTE},
	{"bMemoryType",			0x08, BYTE},
	{"bDataReliability",		0x09, BYTE},
	{"bLogicalBlockSize",		0x0A, BYTE},
	{"qLogicalBlockCount",		0x0B, DDWORD},
	{"dEraseBlockSize",		0x13, DWORD},
	{"bProvisioningType",		0x17, BYTE},
	{"qPhyMemResourceCount",	0x18, DDWORD},
	{"wContextCapabilities",	0x20, WORD},
	{"bLargeUnitGranularity_M1",	0x22, BYTE}
};

struct desc_field_offset device_unit_rpmb_desc_field_name[] = {
	{"bLength",			0x00, BYTE},
	{"bDescriptorType",		0x01, BYTE},
	{"bUnitIndex",			0x02, BYTE},
	{"bLUEnable",			0x03, BYTE},
	{"bBootLunID",			0x04, BYTE},
	{"bLUWriteProtect",		0x05, BYTE},
	{"bLUQueueDepth",		0x06, BYTE},
	{"bPSASensitive",		0x07, BYTE},
	{"bMemoryType",			0x08, BYTE},
	{"bRPMBRegionEnable",		0x09, BYTE},
	{"bLogicalBlockSize",		0x0A, BYTE},
	{"qLogicalBlockCount",		0x0B, DDWORD},
	{"bRPMBRegion0Size",		0x13, BYTE},
	{"bRPMBRegion1Size",		0x14, BYTE},
	{"bRPMBRegion2Size",		0x15, BYTE},
	{"bRPMBRegion3Size",		0x16, BYTE},
	{"bProvisioningType",		0x17, BYTE},
	{"qPhyMemResourceCount",	0x18, DDWORD}
};

struct desc_field_offset device_power_desc_conf_field_name[] = {
	{"bLength",			0x00, BYTE},
	{"bDescriptorType",		0x01, BYTE},
	{"wActiveICCLevelsVCC",		0x02, 32},
	{"wActiveICCLevelsVCCQ",	0x22, 32},
	{"wActiveICCLevelsVCCQ2",	0x42, 32},
};

struct desc_field_offset device_health_desc_conf_field_name[] = {
	{"bLength",		0x00, BYTE},
	{"bDescriptorType",	0x01, BYTE},
	{"bPreEOLInfo",		0x02, BYTE},
	{"bDeviceLifeTimeEstA",	0x03, BYTE},
	{"bDeviceLifeTimeEstB",	0x04, BYTE},
	{"VendorPropInfo",	0x05, 32},
	{"dRefreshTotalCount",	0x25, DWORD},
	{"dRefreshProgress",	0x29, DWORD},
};

enum acc_mode {
	READ_NRML =	(1 << 0),
	READ_ONLY =	(1 << 1),
	WRITE_ONLY =	(1 << 2),
	WRITE_ONCE =	(1 << 3),
	WRITE_PRSIST =	(1 << 4),
	WRITE_VLT =	(1 << 5),
	SET_ONLY =	(1 << 6),
	WRITE_PWR =	(1 << 7),
	MODE_INVALID =	(1 << 8)
};

enum attr_level {
	DEV =		(1 << 0),
	ARRAY =		(1 << 1),
	LEVEL_INVALID =	(1 << 2)
};

enum access_type {
	URD =		(1 << 0),
	UWRT =		(1 << 1),
	ACC_INVALID =	(1 << 2)
};

struct attr_fields {
	char *name;
	enum field_width width_in_bytes;
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

static struct attr_fields ufs_attrs[] = {
	{"bBootLunEn", BYTE, (URD|UWRT), (READ_ONLY|WRITE_PRSIST), DEV},
	{"Reserved", BYTE, (ACC_INVALID), MODE_INVALID, LEVEL_INVALID},
	{"bCurrentPowerMode", BYTE, URD, READ_ONLY, DEV},
	{"bActiveICCLevel", BYTE, (URD|UWRT), (READ_NRML|WRITE_PRSIST), DEV},
	{"bOutOfOrderDataEn", BYTE, (URD|UWRT), (READ_NRML|WRITE_ONCE), DEV},
	{"bBackgroundOpStatus", BYTE, URD, READ_ONLY, DEV},
	{"bPurgeStatus", BYTE, URD, READ_ONLY, DEV},
	{"bMaxDataInSize", BYTE, (URD|UWRT), (READ_NRML|WRITE_PRSIST), DEV},
	{"bMaxDataOutSize", BYTE, (URD|UWRT), (READ_NRML|WRITE_PRSIST), DEV},
	{"dDynCapNeeded", WORD, URD, READ_ONLY, DEV},
	{"bRefClkFreq", BYTE, (URD|UWRT), (READ_NRML|WRITE_PRSIST), DEV},
	{"bConfigDescrLock", BYTE, (URD|UWRT), (READ_NRML|WRITE_ONCE), DEV},
	{"bMaxNumOfRTT", BYTE, (URD|UWRT), (READ_NRML|WRITE_PRSIST), DEV},
	{"wExceptionEventControl", WORD, URD, READ_NRML, DEV},
	{"wExceptionEventStatus", WORD, URD, READ_ONLY, DEV},
	{"dSecondsPassed", DWORD, UWRT, WRITE_ONLY, DEV},
	{"wContextConf", WORD, (URD|UWRT), (READ_NRML|WRITE_VLT), ARRAY},
	{"Reserved", BYTE, ACC_INVALID, MODE_INVALID, LEVEL_INVALID},
	{"Reserved", BYTE, ACC_INVALID, MODE_INVALID, LEVEL_INVALID},
	{"Reserved", BYTE, ACC_INVALID, MODE_INVALID, LEVEL_INVALID},
	{"bDeviceFFUStatus", BYTE, URD, READ_ONLY, DEV},
	{"bPSAState", BYTE, (URD|UWRT), (READ_NRML|WRITE_PRSIST), DEV},
	{"dPSADataSize", DWORD, (URD|UWRT), (READ_NRML|WRITE_PRSIST), DEV},
	{"bRefClkGatingWaitTime", BYTE, URD, READ_ONLY, DEV},
	{"bDeviceCaseRoughTemperaure", BYTE, URD, READ_ONLY, DEV},
	{"bDeviceTooHighTempBoundary", BYTE, URD, READ_ONLY, DEV},
	{"bDeviceTooLowTempBoundary", BYTE, URD, READ_ONLY, DEV},
	{ATTR_RSRV()},
	{ATTR_RSRV()},
	{ATTR_RSRV()},
	{ATTR_RSRV()},
	{ATTR_RSRV()},
	{ATTR_RSRV()},
	{ATTR_RSRV()},
	{ATTR_RSRV()},
	{ATTR_RSRV()},
	{ATTR_RSRV()},
	{ATTR_RSRV()},
	{ATTR_RSRV()},
	{ATTR_RSRV()},
	{ATTR_RSRV()},
	{ATTR_RSRV()},
	{ATTR_RSRV()},
	{ATTR_RSRV()},
	{"bRefreshStatus", BYTE, URD, READ_ONLY, DEV},
	{"bRefreshFreq", BYTE, (URD|UWRT), (READ_NRML|WRITE_PRSIST), DEV},
	{"bRefreshUnit", BYTE, (URD|UWRT), (READ_NRML|WRITE_PRSIST), DEV},
	{"bRefreshMethod", BYTE, (URD|UWRT), (READ_NRML|WRITE_PRSIST), DEV}
};

static struct flag_fields ufs_flags[] = {
	{"Reserved", ACC_INVALID, MODE_INVALID, LEVEL_INVALID},
	{"fDeviceInit", (URD|UWRT), (READ_NRML|SET_ONLY), DEV},
	{"fPermanentWPEn", (URD|UWRT), (READ_NRML|WRITE_ONCE), DEV},
	{"fPowerOnWPEn", (URD|UWRT), (READ_NRML|WRITE_PWR), DEV},
	{"fBackgroundOpsEn", (URD|UWRT), (READ_NRML|WRITE_VLT), DEV},
	{"fDeviceLifeSpanModeEn", (URD|UWRT), (READ_NRML|WRITE_VLT), DEV},
	{"fPurgeEnable", UWRT, (WRITE_ONLY|WRITE_VLT), DEV},
	{"fRefreshEnable", UWRT, (WRITE_ONLY|WRITE_VLT), DEV},
	{"fPhyResourceRemoval", (URD|UWRT), (READ_NRML|WRITE_PRSIST), DEV},
	{"fBusyRTC", URD, READ_ONLY, DEV},
	{"Reserved", ACC_INVALID, MODE_INVALID, LEVEL_INVALID},
	{"fPermanentlyDisableFw", (URD|UWRT), (READ_NRML|WRITE_ONCE), DEV},
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

static int do_unit_desc(int fd, __u8 lun);
static int do_power_desc(int fd);
static int do_conf_desc(int fd, __u8 opt, __u8 index, char *data_file);
static int do_string_desc(int fd, char *str_data, __u8 idn, __u8 opr,
			__u8 index);
int do_query_rq(int fd, struct ufs_bsg_request *bsg_req,
			struct ufs_bsg_reply *bsg_rsp, __u8 query_req_func,
			__u8 opcode, __u8 idn, __u8 index, __u8 sel,
			__u16 req_buf_len, __u16 res_buf_len, __u8 *data_buf);
static int do_read_desc(int fd, struct ufs_bsg_request *bsg_req,
			struct ufs_bsg_reply *bsg_rsp, __u8 idn, __u8 index,
			__u16 desc_buf_len, __u8 *data_buf);
static int do_write_desc(int fd, struct ufs_bsg_request *bsg_req,
			struct ufs_bsg_reply *bsg_rsp, __u8 idn, __u8 index,
			__u16 desc_buf_len, __u8 *data_buf);
static void query_response_error(__u8 opcode, __u8 idn);

static void print_power_desc_icc(__u8 *desc_buf, int vccIndex)
{
	int i, offset = 0;
	struct desc_field_offset *tmp;

	if (vccIndex < 2 ||
		vccIndex > ARRAY_SIZE(device_power_desc_conf_field_name) - 1) {
		print_error("Illegal power desc index %d", vccIndex);
		return;
	}

	tmp = &device_power_desc_conf_field_name[vccIndex];
	offset = tmp->offset;
	printf("\nPower Descriptor %s", tmp->name);
	for (i = offset; i < offset + 32 ; i += 2) {
		printf("\nLevel %2d value : 0x%x", (i - offset)/2,
			be16toh((__u16)desc_buf[i]));
	}
	printf("\n");
}

void print_descriptors(char *desc_str, __u8 *desc_buf,
		struct desc_field_offset *desc_array, int arr_size)
{
	int i;
	struct desc_field_offset *tmp;
	char str_buf[STR_BUF_LEN];

	for (i = 0; i < arr_size; ++i) {
		tmp = &desc_array[i];
		if (tmp->width_in_bytes == BYTE) {
			printf("%s [Byte offset 0x%x]: %s = 0x%x\n", desc_str,
				tmp->offset, tmp->name, desc_buf[tmp->offset]);
		} else if (tmp->width_in_bytes == WORD) {
			printf("%s [Byte offset 0x%x]: %s = 0x%x\n", desc_str,
				tmp->offset, tmp->name,
				be16toh(*(__u16 *)&desc_buf[tmp->offset]));
		} else if (tmp->width_in_bytes == DWORD) {
			printf("%s [Byte offset 0x%x]: %s = 0x%x\n", desc_str,
				tmp->offset, tmp->name,
				be32toh(*(__u32 *)&desc_buf[tmp->offset]));
		} else if (tmp->width_in_bytes == DDWORD) {
			printf("%s [Byte offset 0x%x]: %s = 0x%lx\n",
				desc_str, tmp->offset, tmp->name,
				be64toh(*(__u64 *)&desc_buf[tmp->offset]));
		} else if ((tmp->width_in_bytes > DDWORD) &&
				tmp->width_in_bytes < STR_BUF_LEN) {
			memset(str_buf, 0, STR_BUF_LEN);
			memcpy(str_buf, &desc_buf[tmp->offset],
				tmp->width_in_bytes);
			printf("%s [Byte offset 0x%x]: %s = %s\n", desc_str,
				tmp->offset, tmp->name, str_buf);
		} else {
			printf("%s [Byte offset 0x%x]: %s Wrong Width = %d",
				desc_str, tmp->offset, tmp->name,
				tmp->width_in_bytes);
		}
	}
}

static char *access_type_string(__u8 current_att, __u8 config_type,
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

	if (mode & READ_NRML)
		strcat(access_string, " | Read");
	if (mode & READ_ONLY)
		strcat(access_string, " | ReadOnly");
	if (mode & WRITE_ONLY)
		strcat(access_string, " | WriteOnly");
	if (mode & WRITE_ONCE)
		strcat(access_string, " | WriteOnce");
	if (mode & WRITE_PRSIST)
		strcat(access_string, " | Persistent");
	if (mode & WRITE_VLT)
		strcat(access_string, " | Volatile");
	if (mode & SET_ONLY)
		strcat(access_string, " | SetOnly");
	if (mode & WRITE_PWR)
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
	printf("\n\t-r\t read operation (default) for readable descriptors\n");
	printf("\n\t-w\t write operation , for writable descriptors\n");
	printf("\t\t Set the input configuration file after -w opt\n");
	printf("\t\t for Configuration descriptor\n");
	printf("\t\t Set the input string after -w opt\n");
	printf("\t\t for String descriptor\n");
	printf("\n\t-i\t Set index parameter(default = 0)\n");
	printf("\n\t-p\t path to ufs bsg device\n");
}

void attribute_help(char *tool_name)
{
	__u8 current_att = 0;
	char access_string[100] = {0};

	printf("\n Attributes command usage:\n");
	printf("\n\t%s attr [-t] <attr_idn> [-a|-r|-w] <data_hex> [-p]"
		" <device_path> \n", tool_name);
	printf("\n\t-t\t Attributes type idn\n"
		"\t\t Available attributes and its access based on"
		" UFS ver 3.0 :\n");

	while (current_att < ARRAY_SIZE(ufs_attrs)) {
		printf("\t\t\t %-3d: %-25s %s\n",
			current_att,
			ufs_attrs[current_att].name,
			access_type_string(current_att, ATTR_TYPE,
			access_string));
		current_att++;
		memset(access_string, 0, 100);
	}

	printf("\n\t-a\tread and print all readable attributes"
		" for the device\n");
	printf("\n\t-r\tread operation (default), for readable attribute(s)\n");
	printf("\n\t-w\twrite operation (with hex data),"
		" for writable attribute\n");
	printf("\n\t-p\tpath to ufs bsg device\n");
	printf("\n\tExample - Read bBootLunEn\n"
		"\t\t%s attr -t 0 -p /dev/ufs-bsg\n", tool_name);
}

void flag_help(char *tool_name)
{
	__u8 current_flag = 0;
	char access_string[100] = {0};

	printf("\n Flags command usage:\n");
	printf("\n\t%s fl [-t] <flag idn> [-a|-r|-o|-e] [-p]"
		" <device_path>\n", tool_name);
	printf("\n\t-t\t Flags type idn\n"
		"\t\t Available flags and its access, based on UFS ver 3.0 :\n");

	while (current_flag < QUERY_FLAG_IDN_MAX) {
		printf("\t\t\t %-3d: %-25s %s\n", current_flag,
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
	printf("\n\t-p\t path to ufs bsg device\n");
	printf("\n\tExample - Read the bkops operation flag\n"
		"\t\t%s fl -t 4 -p /dev/ufs-bsg\n", tool_name);
}

int do_device_desc(int fd, __u8 *desc_buff)
{
	struct ufs_bsg_request bsg_req = {0};
	struct ufs_bsg_reply bsg_rsp = {0};
	__u8 data_buf[QUERY_DESC_DEVICE_MAX_SIZE] = {0};
	int rc = 0;

	rc = do_read_desc(fd, &bsg_req, &bsg_rsp,
			QUERY_DESC_IDN_DEVICE, 0,
			QUERY_DESC_DEVICE_MAX_SIZE, data_buf);
	if (rc) {
		print_error("Could not read device descriptor , error %d", rc);
		goto out;
	}
	if(!desc_buff)
		print_descriptors("Device Descriptor", data_buf,
				device_desc_field_name,
				ARRAY_SIZE(device_desc_field_name));
	else
		memcpy(desc_buff, data_buf, QUERY_DESC_DEVICE_MAX_SIZE);

out:
	return rc;
}

static int do_unit_desc(int fd, __u8 lun)
{
	struct ufs_bsg_request bsg_req = {0};
	struct ufs_bsg_reply bsg_rsp = {0};
	__u8 data_buf[QUERY_DESC_UNIT_MAX_SIZE] = {0};
	int ret = 0;

	ret = do_read_desc(fd, &bsg_req, &bsg_rsp, QUERY_DESC_IDN_UNIT, lun,
			QUERY_DESC_UNIT_MAX_SIZE, data_buf);
	if (ret) {
		print_error("Could not read unit descriptor error", ret);
		goto out;
	}

	if (lun == 0xc4)
		print_descriptors("RPMB LUN Descriptor", data_buf,
				device_unit_rpmb_desc_field_name,
				ARRAY_SIZE(device_unit_rpmb_desc_field_name));
	else
		print_descriptors("LUN Descriptor", data_buf,
				device_unit_desc_field_name,
				ARRAY_SIZE(device_unit_desc_field_name));


out:
	return ret;
}

static int do_interconnect_desc(int fd)
{
	struct ufs_bsg_request bsg_req = {0};
	struct ufs_bsg_reply bsg_rsp = {0};
	__u8 data_buf[QUERY_DESC_INTERCONNECT_MAX_SIZE] = {0};
	int ret = 0;

	ret = do_read_desc(fd, &bsg_req, &bsg_rsp, QUERY_DESC_IDN_INTERCONNECT,
			0, QUERY_DESC_INTERCONNECT_MAX_SIZE, data_buf);
	if (ret) {
		print_error("Could not read interconnect descriptor error %d",
			ret);
		goto out;
	}

	print_descriptors("Interconnect Descriptor", data_buf,
			device_interconnect_desc_conf_field_name,
			ARRAY_SIZE(device_interconnect_desc_conf_field_name));

out:
	return ret;
}

static int do_geo_desc(int fd)
{
	struct ufs_bsg_request bsg_req = {0};
	struct ufs_bsg_reply bsg_rsp = {0};
	__u8 data_buf[QUERY_DESC_GEOMETRY_MAX_SIZE] = {0};
	int ret = 0;

	ret = do_read_desc(fd, &bsg_req, &bsg_rsp, QUERY_DESC_IDN_GEOMETRY, 0,
			QUERY_DESC_GEOMETRY_MAX_SIZE, data_buf);
	if (ret) {
		print_error("Could not read geometry descriptor , error %d",
			ret);
		goto out;
	}

	print_descriptors("Geometry Descriptor", data_buf,
			device_geo_desc_conf_field_name,
			ARRAY_SIZE(device_geo_desc_conf_field_name));

out:
	return ret;
}

static int do_power_desc(int fd)
{
	struct ufs_bsg_request bsg_req = {0};
	struct ufs_bsg_reply bsg_rsp = {0};
	__u8 data_buf[QUERY_DESC_POWER_MAX_SIZE] = {0};
	int ret = 0;

	ret = do_read_desc(fd, &bsg_req, &bsg_rsp,
			QUERY_DESC_IDN_POWER, 0, QUERY_DESC_POWER_MAX_SIZE,
			data_buf);
	if (ret) {
		print_error("Could not read power descriptor , error %d", ret);
		goto out;
	}

	printf("Power Descriptor[Byte offset 0x%x]: %s = 0x%x\n",
		device_power_desc_conf_field_name[0].offset,
		device_power_desc_conf_field_name[0].name, data_buf[0]);

	printf("Power Descriptor[Byte offset 0x%x]: %s = 0x%x\n",
		device_power_desc_conf_field_name[1].offset,
		device_power_desc_conf_field_name[1].name, data_buf[1]);

	print_power_desc_icc(data_buf, 2);
	print_power_desc_icc(data_buf, 3);
	print_power_desc_icc(data_buf, 4);

out:
	return ret;
}

static int do_health_desc(int fd)
{
	struct ufs_bsg_request bsg_req = {0};
	struct ufs_bsg_reply bsg_rsp = {0};
	__u8 data_buf[QUERY_DESC_HEALTH_MAX_SIZE] = {0};
	int ret = 0;

	ret = do_read_desc(fd, &bsg_req, &bsg_rsp, QUERY_DESC_IDN_HEALTH, 0,
			QUERY_DESC_HEALTH_MAX_SIZE, data_buf);
	if (ret) {
		print_error("Could not read device health descriptor error %d",
			ret);
		goto out;
	}

	print_descriptors("Device Health Descriptor:", data_buf,
			device_health_desc_conf_field_name,
			ARRAY_SIZE(device_health_desc_conf_field_name));

out:
	return ret;
}

static void create_str_desc_data(__u8 *dest_buf, const char *str, __u8 len)
{
	int j = 3;
	int i;

	dest_buf[0] = len * 2 + 2;
	dest_buf[1] = QUERY_DESC_IDN_STRING;
	for (i = 0; i < len ; i++) {
		dest_buf[j] = *(str++);
		j = j + 2;
	}
}

static int do_string_desc(int fd, char *str_data, __u8 idn, __u8 opr,
			__u8 index)
{
	int rc = 0;
	__u8 data_buf[QUERY_DESC_STRING_MAX_SIZE] = {0};
	struct ufs_bsg_request bsg_req = {0};
	struct ufs_bsg_reply bsg_rsp = {0};
	int len, i;

	if (opr == WRITE) {
		len = strlen(str_data);
		create_str_desc_data(data_buf, str_data, len);
		rc = do_write_desc(fd, &bsg_req, &bsg_rsp,
				QUERY_DESC_IDN_STRING, index,
				len * 2 + 2, data_buf);
		if (rc == OK)
			printf("\nString Descriptor was written\n");
	} else {
		rc = do_read_desc(fd, &bsg_req, &bsg_rsp, QUERY_DESC_IDN_STRING,
				index, QUERY_DESC_STRING_MAX_SIZE, data_buf);
		if (!rc) {
			printf("\nString Desc(Row data):\n");
			for (i = 0; i < bsg_rsp.reply_payload_rcv_len; i++)
				printf("0x%02x ", data_buf[i]);
			printf("\n");
		}
	}
	return rc;
}

static int do_conf_desc(int fd, __u8 opt, __u8 index, char *data_file)
{
	int rc = OK;
	struct ufs_bsg_request bsg_req = {0};
	struct ufs_bsg_reply bsg_rsp = {0};
	__u8 conf_desc_buf[QUERY_DESC_CONFIGURAION_MAX_SIZE] = {0};
	int offset, i;
	int data_fd;
	char *filename_header = "config_desc_data_ind_%d";
	char output_file[30] = {0};

	if (opt == WRITE) {
		data_fd = open(data_file, O_RDONLY);
		if (data_fd < 0) {
			perror("can't open input file");
			return ERROR;
		}
		if (read(data_fd, conf_desc_buf,
			QUERY_DESC_CONFIGURAION_MAX_SIZE) !=
			QUERY_DESC_CONFIGURAION_MAX_SIZE) {
			print_error("Could not read config data from  %s file",
				data_file);
			rc = ERROR;
			goto out;
		}

		rc = do_write_desc(fd, &bsg_req, &bsg_rsp,
				QUERY_DESC_IDN_CONFIGURAION, index,
				QUERY_DESC_CONFIGURAION_MAX_SIZE,
				conf_desc_buf);
		if (!rc)
			printf("Config Descriptor was written to device\n");
	} else {
		rc = do_read_desc(fd, &bsg_req, &bsg_rsp,
				QUERY_DESC_IDN_CONFIGURAION,
				index, QUERY_DESC_CONFIGURAION_MAX_SIZE,
				conf_desc_buf);
		if (!rc)
			print_descriptors("Config Device Descriptor:",
				conf_desc_buf,
				device_config_desc_field_name,
				ARRAY_SIZE(device_config_desc_field_name));

		for (i = 0 ; i < 8; i++) {
			offset = (16 * (i+1));
			printf("Config %d Unit Descriptor:\n", i);
			print_descriptors("Config Descriptor:",
				conf_desc_buf + offset,
				device_config_unit_desc_field_name,
				ARRAY_SIZE(device_config_unit_desc_field_name));
		}
		sprintf(output_file, filename_header, index);
		data_fd = open(output_file, O_WRONLY | O_CREAT,
				S_IRUSR | S_IWUSR);
		if (data_fd < 0) {
			perror("can't open output file");
			return ERROR;
		}
		if (write(data_fd, conf_desc_buf,
			QUERY_DESC_CONFIGURAION_MAX_SIZE) !=
			QUERY_DESC_CONFIGURAION_MAX_SIZE) {
			print_error("Could not write config data into %s file",
				output_file);
			rc = ERROR;
			goto out;
		}
		printf("Config Descriptor was written into %s file\n",
			output_file);
	}
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
		print_error("open");
		return ERROR;
	}

	if (opt->opr == READ_ALL) {
		if (do_device_desc(fd, NULL) || do_unit_desc(fd, 0) ||
			do_interconnect_desc(fd) || do_geo_desc(fd) ||
			do_power_desc(fd) || do_health_desc(fd))
			rc = ERROR;
		goto out;
	}

	switch (opt->idn) {
	case QUERY_DESC_IDN_DEVICE:
		rc = do_device_desc(fd, NULL);
		break;
	case QUERY_DESC_IDN_CONFIGURAION:
		if (opt->opr == READ)
			rc = do_conf_desc(fd, opt->opr, opt->index, NULL);
		else
			rc = do_conf_desc(fd, opt->opr, opt->index,
					(char *)opt->data);
		break;
	case QUERY_DESC_IDN_UNIT:
		rc = do_unit_desc(fd, opt->index);
		break;
	case QUERY_DESC_IDN_GEOMETRY:
		rc = do_geo_desc(fd);
		break;
	case QUERY_DESC_IDN_POWER:
		rc = do_power_desc(fd);
		break;
	case QUERY_DESC_IDN_STRING:
		rc = do_string_desc(fd, (char *)opt->data, opt->idn, opt->opr,
				opt->index);
		break;
	case QUERY_DESC_IDN_HEALTH:
		rc = do_health_desc(fd);
		break;
	case QUERY_DESC_IDN_INTERCONNECT:
		rc = do_interconnect_desc(fd);
		break;
	default:
		print_error("Unsupported Descriptor type %d", opt->idn);
		rc = -EINVAL;
		break;
	}

out:
	close(fd);
	return rc;
}

void print_attribute(struct attr_fields *attr, __u8 *attr_buffer)
{
	if (attr->width_in_bytes == BYTE)
		printf("%-26s := 0x%02x\n", attr->name, attr_buffer[0]);
	else if (attr->width_in_bytes == WORD)
		printf("%-26s := 0x%04x\n", attr->name, *(__u16 *)attr_buffer);
	else if (attr->width_in_bytes == DWORD)
		printf("%-26s := 0x%08x\n", attr->name,
			be32toh(*(__u32 *)attr_buffer));
}

int do_query_rq(int fd, struct ufs_bsg_request *bsg_req,
			struct ufs_bsg_reply *bsg_rsp, __u8 query_req_func,
			__u8 opcode, __u8 idn, __u8 index, __u8 sel,
			__u16 req_buf_len, __u16 res_buf_len, __u8 *data_buf)
{
	int rc = OK;
	__u8 res_code;
	__u16 len = res_buf_len;

	if (req_buf_len > 0)
		len = req_buf_len;

	prepare_upiu(bsg_req, query_req_func, len, opcode, idn,
		index, sel);

	rc = send_bsg_scsi_trs(fd, bsg_req, bsg_rsp, req_buf_len, res_buf_len,
			data_buf);

	if (rc) {
		print_error("%s: query failed, status %d idn: %d, i: %d, s: %d",
			__func__, rc, idn, index);
		rc = ERROR;
		goto out;
	}

	res_code = (be32toh(bsg_rsp->upiu_rsp.header.dword_1) >> 8) & 0xff;
	if (res_code) {
		query_response_error(res_code, idn);
		rc = ERROR;
	}

out:
	return rc;
}

static int do_write_desc(int fd, struct ufs_bsg_request *bsg_req,
			struct ufs_bsg_reply *bsg_rsp, __u8 idn, __u8 index,
			__u16 desc_buf_len, __u8 *data_buf)
{
	return do_query_rq(fd, bsg_req, bsg_rsp,
			UPIU_QUERY_FUNC_STANDARD_WRITE_REQUEST,
			UPIU_QUERY_OPCODE_WRITE_DESC, idn, index,
			0, desc_buf_len, 0, data_buf);
}

static int do_read_desc(int fd, struct ufs_bsg_request *bsg_req,
			struct ufs_bsg_reply *bsg_rsp, __u8 idn, __u8 index,
			__u16 desc_buf_len, __u8 *data_buf)
{
	return do_query_rq(fd, bsg_req, bsg_rsp,
			UPIU_QUERY_FUNC_STANDARD_READ_REQUEST,
			UPIU_QUERY_OPCODE_READ_DESC, idn, index, 0,
			0, desc_buf_len, data_buf);
}

int do_attributes(struct tool_options *opt)
{
	int fd;
	int rc = OK;
	struct attr_fields *tmp = NULL;
	int oflag = O_RDWR;
	__u8 att_idn;
	__u32 attr_value;
	struct ufs_bsg_request bsg_req = {0};
	struct ufs_bsg_reply bsg_rsp = {0};

	if (opt->opr == READ_ALL || opt->opr == READ)
		oflag = O_RDONLY;

	fd = open(opt->path, oflag);
	if (fd < 0) {
		print_error("open");
		return ERROR;
	}

	tmp = &ufs_attrs[opt->idn];

	if (opt->opr == READ_ALL) {
		att_idn = QUERY_ATTR_IDN_BOOT_LU_EN;

		while (att_idn < ARRAY_SIZE(ufs_attrs)) {
			tmp = &ufs_attrs[att_idn];
			if (tmp->acc_type == ACC_INVALID ||
				tmp->acc_mode == WRITE_ONLY) {
				att_idn++;
				continue;
			}

			rc = do_query_rq(fd, &bsg_req, &bsg_rsp,
					UPIU_QUERY_FUNC_STANDARD_READ_REQUEST,
					UPIU_QUERY_OPCODE_READ_ATTR, att_idn,
					opt->index, opt->selector, 0, 0, 0);
			if (rc == OK) {
				attr_value = be32toh(bsg_rsp.upiu_rsp.qr.value);
				print_attribute(tmp, (__u8 *)&attr_value);
			}

			memset(&bsg_rsp, 0, BSG_REPLY_SZ);
			att_idn++;
		}
	} else if (opt->opr == WRITE) {
		if (tmp->acc_type == ACC_INVALID ||
				tmp->acc_mode == READ_ONLY) {
			print_error("%s Attribute is not writable", tmp->name);
			rc = ERROR;
			goto out;
		}

		attr_value = *(__u32 *)opt->data;
		switch (tmp->width_in_bytes) {
		case BYTE:
			if (attr_value > 0xFF) {
				print_error("Wrong write data for %s attr\n",
					tmp->name);
				rc = ERROR;
				goto out;
			}
			break;
		case WORD:
			if (attr_value > 0xFFFF) {
				print_error("Wrong write data for %s attr\n",
					tmp->name);
				rc = ERROR;
				goto out;
			}
			break;
		case DWORD:
			/* avoid -Wswitch warning - no need to check value */
			break;
		default:
			print_error("Unsupported width %d",
					tmp->width_in_bytes);
			rc = ERROR;
			goto out;
		}

		bsg_req.upiu_req.qr.value = htobe32(attr_value);
		rc = do_query_rq(fd, &bsg_req, &bsg_rsp,
				UPIU_QUERY_FUNC_STANDARD_WRITE_REQUEST,
				UPIU_QUERY_OPCODE_WRITE_ATTR, opt->idn,
				opt->index, opt->selector, 0, 0, 0);
	} else if (opt->opr == READ) {
		if (tmp->acc_type == ACC_INVALID ||
			tmp->acc_mode == WRITE_ONLY) {
			print_error("%s attribute is not readable", tmp->name);
			rc = ERROR;
			goto out;
		}

		rc = do_query_rq(fd, &bsg_req, &bsg_rsp,
				UPIU_QUERY_FUNC_STANDARD_READ_REQUEST,
				UPIU_QUERY_OPCODE_READ_ATTR, opt->idn,
				opt->index, opt->selector, 0, 0, 0);
		if (rc == OK) {
			attr_value = be32toh(bsg_rsp.upiu_rsp.qr.value);
			print_attribute(tmp, (__u8 *)&attr_value);
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
	__u8 opcode, flag_idn;
	struct flag_fields *tmp;
	struct ufs_bsg_request bsg_req = {0};
	struct ufs_bsg_reply bsg_rsp = {0};
	int oflag = O_RDWR;

	if (opt->opr == READ_ALL || opt->opr == READ)
		oflag = O_RDONLY;

	fd = open(opt->path, oflag);
	if (fd < 0) {
		print_error("open");
		return ERROR;
	}

	tmp = &ufs_flags[opt->idn];

	switch (opt->opr) {
	case READ_ALL:
		flag_idn = QUERY_FLAG_IDN_FDEVICEINIT;
		printf("UFS Device Flags:\n");
		while (flag_idn < QUERY_FLAG_IDN_MAX) {
			tmp = &ufs_flags[flag_idn];
			if (tmp->acc_type == ACC_INVALID ||
				tmp->acc_type == UWRT) {
				flag_idn++;
				continue;
			}

			rc = do_query_rq(fd, &bsg_req, &bsg_rsp,
					UPIU_QUERY_FUNC_STANDARD_READ_REQUEST,
					UPIU_QUERY_OPCODE_READ_FLAG, flag_idn,
					opt->index, opt->selector, 0, 0, 0);
			if (rc == OK) {
				printf("%-26s := 0x%01x\n", tmp->name,
					be32toh(bsg_rsp.upiu_rsp.qr.value) &
					0xff);
			} else {
				/* on failuire make note and keep going */
				print_error("%s flag read failed for flag %s",
					tmp->name);
			}

			memset(&bsg_rsp, 0, BSG_REPLY_SZ);
			flag_idn++;
		}
	break;
	case CLEAR_FLAG:
	case TOGGLE_FLAG:
	case SET_FLAG:
		if (tmp->acc_type == ACC_INVALID ||
			tmp->acc_mode == READ_ONLY) {
			print_error("%s flag is not writable", tmp->name);
			rc = ERROR;
		} else if ((tmp->acc_mode & SET_ONLY) &&
			opt->opr != SET_FLAG) {
			print_error("Only set operation supported for %s flag",
				tmp->name);
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
					opcode, opt->idn, opt->index,
					opt->selector, 0, 0, 0);
			if (rc)
				print_error("%s flag write failed for flag %s",
					tmp->name);
		}
	break;
	case READ:/*Read operation */
		if (tmp->acc_type == ACC_INVALID || tmp->acc_type == UWRT) {
			print_error("%s flag is not readable", tmp->name);
			rc = ERROR;
		} else {
			rc = do_query_rq(fd, &bsg_req, &bsg_rsp,
					UPIU_QUERY_FUNC_STANDARD_READ_REQUEST,
					UPIU_QUERY_OPCODE_READ_FLAG, opt->idn,
					opt->index, opt->selector, 0, 0, 0);
			if (rc == OK)
				printf("%-26s := 0x%01x\n", tmp->name,
					be32toh(bsg_rsp.upiu_rsp.qr.value) &
					0xff);
			else
				print_error("%s flag read failed for flag %s",
					tmp->name);
		}
	break;
	default:
		print_error("Unsupported operation for %s flag", tmp->name);
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
	case ERR_HIST_TYPE:
		err_hist_help(prgname);
		break;
	case FFU_TYPE:
		ffu_help(prgname);
		break;
	case UIC_TYPE:
		unipro_help(prgname);
		break;
	default:
		print_error("Unsupported cmd type");
		break;
	}
}
