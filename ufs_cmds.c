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
#include <endian.h>
#include <errno.h>
#include <stdint.h>
#include <stdbool.h>
#include <dirent.h>

#include "ufs.h"
#include "ufs_cmds.h"
#include "options.h"

#define STR_BUF_LEN 33
#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))
#define ATTR_RSRV() "Reserved", BYTE, ACC_INVALID, MODE_INVALID, LEVEL_INVALID
#define ATTR_VENDOR() "VendorSpecificAttr", BYTE, (URD|UWRT), (READ_NRML|WRITE_VLT)
#define FLAG_RSRV() "Reserved", ACC_INVALID, MODE_INVALID, LEVEL_INVALID
#define FLAG_VENDOR() "VendorSpecificFlag",  (URD|UWRT), (READ_NRML|WRITE_VLT)

#define CONFIG_HEADER_OFFSET 0x16
#define CONFIG_LUN_OFFSET 0x1A

/* Config desc. offsets for UFS 2.0 - 3.0 spec */
#define CONFIG_HEADER_OFFSET_3_0 0x10
#define CONFIG_LUN_OFFSET_3_0 0x10

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
	{"iProductRevisionLevel",	0x2A, BYTE},
	{"Reserved1",			0x2B, BYTE},
	{"Reserved2",			0x2C, DWORD},
	{"Reserved3",			0x30, DWORD},
	{"Reserved4",			0x34, DWORD},
	{"Reserved5",			0x38, DWORD},
	{"Reserved6",			0x3c, DWORD},
	{"wHPBVersion",			0x40, WORD},
	{"bHPBControl",			0x42, BYTE},
	{"Reserved8",			0x43, DWORD},
	{"Reserved9",			0x47, DDWORD},
	{"dExtendedUFSFeaturesSupport",	0x4F, DWORD},
	{"bWriteBoosterBufferPreserveUserSpaceEn", 0x53, BYTE},
	{"bWriteBoosterBufferType",	0x54, BYTE},
	{"dNumSharedWriteBoosterBufferAllocUnits", 0x55, DWORD}
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
	{"bHPBControl",		0x0B, BYTE},
	{"bRPMBRegionEnable",	0x0C, BYTE},
	{"bRPMBRegion1Size",	0x0D, BYTE},
	{"bRPMBRegion2Size",	0x0E, BYTE},
	{"bRPMBRegion3Size",	0x0F, BYTE},
	{"bWriteBoosterBufferPreserveUserSpaceEn", 0x10, BYTE},
	{"bWriteBoosterBufferType",	0x11, BYTE},
	{"dNumSharedWriteBoosterBufferAllocUnits", 0x12, DWORD}
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
	{"wContextCapabilities",	0x0B, WORD},
	{"wLUMaxActiveHPBRegions",	0x10, WORD},
	{"wHPBPinnedRegionStartIdx",	0x12, WORD},
	{"wNumHPBPinnedRegions",	0x14, WORD},
	{"dLUNumWriteBoosterBufferAllocUnits", 0x16, DWORD}
};

struct desc_field_offset device_geo_desc_conf_field_name[] = {
	{"bLength",				0x00, BYTE},
	{"bDescriptorType ",			0x01, BYTE},
	{"bMediaTechnology",			0x02, BYTE},
	{"qTotalRawDeviceCapacity",		0x04, DDWORD},
	{"bMaxNumberLU",			0x0C, BYTE},
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
	{"wSystemCodeCapAdjFac",		0x24, WORD},
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
	{"dOptimalLogicalBlockSize",		0X44, DWORD},
	{"bHPBRegionSize",			0X48, BYTE},
	{"bHPBNumberLU",			0X49, BYTE},
	{"bHPBSubRegionSize",			0X4a, BYTE},
	{"wDeviceMaxActiveHPBRegions",		0X4b, WORD},
	{"Reserved",				0X4d, WORD},
	{"dWriteBoosterBufferMaxNAllocUnits",	0X4f, DWORD},
	{"bDeviceMaxWriteBoosterLUs",		0X53, BYTE},
	{"bWriteBoosterBufferCapAdjFac",	0X54, BYTE},
	{"bSupportedWriteBoosterBufferUserSpaceReductionTypes", 0X55, BYTE},
	{"bSupportedWriteBoosterBufferTypes", 0X56, BYTE}
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
	{"bLargeUnitGranularity_M1",	0x22, BYTE},
	{"wLUMaxActiveHPBRegions",	0x23, WORD},
	{"wHPBPinnedRegionStartIdx",	0x25, WORD},
	{"wNumHPBPinnedRegions",	0x27, WORD},
	{"dLUNumWriteBoosterBufferAllocUnits",	0x29, DWORD}
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
	{"qPhyMemResourceCount",	0x18, DDWORD},
	{"Reserved",			0x20, WORD},
	{"Reserved",			0x22, BYTE},
};

struct desc_field_offset device_power_desc_conf_field_name[] = {
	{"bLength",			0x00, BYTE},
	{"bDescriptorType",		0x01, BYTE},
	{"wActiveICCLevelsVCC",		0x02, 32},
	{"wActiveICCLevelsVCCQ",	0x22, 32},
	{"wActiveICCLevelsVCCQ2",	0x42, 32}
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

struct desc_field_offset device_fbo_desc_field_name[] = {
	{"bLength",				0x00, BYTE},
	{"wFBOVersion",				0x01, WORD},
	{"dFBORecommendedLBARangeSize",		0x03, DWORD},
	{"dFBOMaxLBARangeSize",			0x07, DWORD},
	{"dFBOMinLBARangeSize",			0x0b, DWORD},
	{"bFBOMaxLBARangeCount",		0x0f, BYTE},
	{"wFBOLBARangeAlignment",		0x10, WORD}
};

struct query_err_res {
	char *name;
	__u8 opcode;
};

struct attr_fields ufs_attrs[] = {
	{"bBootLunEn", BYTE, (URD|UWRT), (READ_ONLY|WRITE_PRSIST), DEV},
	{"bMAX_DATA_SIZE_FOR_HPB_SINGLE_CMD", BYTE, URD, READ_ONLY, DEV},
	{"bCurrentPowerMode", BYTE, URD, READ_ONLY, DEV},
	{"bActiveICCLevel", BYTE, (URD|UWRT), (READ_NRML|WRITE_PRSIST), DEV},
	{"bOutOfOrderDataEn", BYTE, (URD|UWRT), (READ_NRML|WRITE_ONCE), DEV},
	{"bBackgroundOpStatus", BYTE, URD, READ_ONLY, DEV},
	{"bPurgeStatus", BYTE, URD, READ_ONLY, DEV},
	{"bMaxDataInSize", BYTE, (URD|UWRT), (READ_NRML|WRITE_PRSIST), DEV},
	{"bMaxDataOutSize", BYTE, (URD|UWRT), (READ_NRML|WRITE_PRSIST), DEV},
	{"dDynCapNeeded", WORD, URD, READ_ONLY, ARRAY},
	{"bRefClkFreq", BYTE, (URD|UWRT), (READ_NRML|WRITE_PRSIST), DEV},
	{"bConfigDescrLock", BYTE, (URD|UWRT), (READ_NRML|WRITE_ONCE), DEV},
	{"bMaxNumOfRTT", BYTE, (URD|UWRT), (READ_NRML|WRITE_PRSIST), DEV},
	{"wExceptionEventControl", WORD, URD, (READ_NRML|WRITE_VLT), DEV},
	{"wExceptionEventStatus", WORD, URD, READ_ONLY, DEV},
	{"dSecondsPassed", DWORD, UWRT, WRITE_ONLY, DEV},
	{"wContextConf", WORD, (URD|UWRT), (READ_NRML|WRITE_VLT), ARRAY},
	{ATTR_RSRV()},
	{ATTR_RSRV()},
	{ATTR_RSRV()},
	{"bDeviceFFUStatus", BYTE, URD, READ_ONLY, DEV},
	{"bPSAState", BYTE, (URD|UWRT), (READ_NRML|WRITE_PRSIST), DEV},
	{"dPSADataSize", DWORD, (URD|UWRT), (READ_NRML|WRITE_PRSIST), DEV},
	{"bRefClkGatingWaitTime", BYTE, URD, READ_ONLY, DEV},
	{"bDeviceCaseRoughTemperaure", BYTE, URD, READ_ONLY, DEV},
	{"bDeviceTooHighTempBoundary", BYTE, URD, READ_ONLY, DEV},
/*1A*/	{"bDeviceTooLowTempBoundary", BYTE, URD, READ_ONLY, DEV},
/*1B*/	{"bThrottlingStatus", BYTE, URD, READ_ONLY, DEV},
/*1C*/	{"bWBBufFlushStatus", BYTE, URD, READ_ONLY, DEV | ARRAY},
/*1D*/	{"bAvailableWBBufSize", BYTE, URD, READ_ONLY, DEV | ARRAY},
/*1E*/	{"bWBBufLifeTimeEst", BYTE, URD, READ_ONLY, DEV | ARRAY},
/*1F*/	{"bCurrentWBBufSize", DWORD, URD, READ_ONLY, DEV | ARRAY},
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
/*2A*/	{"bEXTIIDEn", BYTE, (URD|UWRT), (READ_NRML|WRITE_ONCE), DEV},
/*2B*/	{"wHostHintCacheSize", BYTE, (URD|UWRT), (READ_NRML|WRITE_PRSIST), DEV},
/*2C*/	{"bRefreshStatus", BYTE, URD, READ_ONLY, DEV},
/*2D*/	{"bRefreshFreq", BYTE, (URD|UWRT), (READ_NRML|WRITE_PRSIST), DEV},
/*2E*/	{"bRefreshUnit", BYTE, (URD|UWRT), (READ_NRML|WRITE_PRSIST), DEV},
/*2F*/	{"bRefreshMethod", BYTE, (URD|UWRT), (READ_NRML|WRITE_PRSIST), DEV},
/*30*/	{ATTR_RSRV()},
/*31h*/ {"bFBOControl", BYTE, UWRT, WRITE_ONLY, DEV},
/*32h*/ {"bFBOExecuteThreshold", BYTE, (URD|UWRT), (READ_NRML|WRITE_VLT), DEV},
/*33h*/ {"bFBOProgressState", BYTE, URD, READ_ONLY, DEV},
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
	{ATTR_RSRV()},
	{ATTR_RSRV()},
	{ATTR_RSRV()},
	{ATTR_RSRV()},
	{ATTR_RSRV()},
	{ATTR_RSRV()},
	{ATTR_RSRV()},
	{ATTR_VENDOR()},
	{ATTR_VENDOR()},
	{ATTR_VENDOR()},
	{ATTR_VENDOR()},
	{ATTR_VENDOR()},
	{ATTR_VENDOR()},
	{ATTR_VENDOR()},
	{ATTR_VENDOR()},
	{ATTR_VENDOR()},
	{ATTR_VENDOR()},
	{ATTR_VENDOR()},
	{ATTR_VENDOR()},
	{ATTR_VENDOR()},
	{ATTR_VENDOR()},
	{ATTR_VENDOR()},
	{ATTR_VENDOR()},
	{ATTR_VENDOR()},
	{ATTR_VENDOR()},
	{ATTR_VENDOR()},
	{ATTR_VENDOR()},
	{ATTR_VENDOR()},
	{ATTR_VENDOR()},
	{ATTR_VENDOR()},
	{ATTR_VENDOR()},
	{ATTR_VENDOR()},
	{ATTR_VENDOR()},
	{ATTR_VENDOR()},
	{ATTR_VENDOR()},
	{ATTR_VENDOR()},
	{ATTR_VENDOR()},
	{ATTR_VENDOR()},
	{ATTR_VENDOR()},
	{ATTR_VENDOR()},
	{ATTR_VENDOR()},
	{ATTR_VENDOR()},
	{ATTR_VENDOR()},
	{ATTR_VENDOR()},
	{ATTR_VENDOR()},
	{ATTR_VENDOR()},
	{ATTR_VENDOR()},
	{ATTR_VENDOR()},
	{ATTR_VENDOR()},
	{ATTR_VENDOR()},
	{ATTR_VENDOR()},
	{ATTR_VENDOR()},
	{ATTR_VENDOR()},
	{ATTR_VENDOR()},
	{ATTR_VENDOR()},
	{ATTR_VENDOR()},
	{ATTR_VENDOR()},
	{ATTR_VENDOR()},
	{ATTR_VENDOR()},
	{ATTR_VENDOR()},
	{ATTR_VENDOR()},
	{ATTR_VENDOR()},
	{ATTR_VENDOR()},
	{ATTR_VENDOR()},
	{ATTR_VENDOR()},
	{ATTR_VENDOR()},
	{ATTR_VENDOR()},
	{ATTR_VENDOR()},
	{ATTR_VENDOR()},
	{ATTR_VENDOR()},
	{ATTR_VENDOR()},
	{ATTR_VENDOR()},
	{ATTR_VENDOR()},
	{ATTR_VENDOR()},
	{ATTR_VENDOR()},
	{ATTR_VENDOR()},
	{ATTR_VENDOR()},
	{ATTR_VENDOR()},
	{ATTR_VENDOR()},
	{ATTR_VENDOR()},
	{ATTR_VENDOR()},
	{ATTR_VENDOR()},
	{ATTR_VENDOR()},
	{ATTR_VENDOR()},
	{ATTR_VENDOR()},
	{ATTR_VENDOR()},
	{ATTR_VENDOR()},
	{ATTR_VENDOR()},
	{ATTR_VENDOR()},
	{ATTR_VENDOR()},
	{ATTR_VENDOR()},
	{ATTR_VENDOR()},
	{ATTR_VENDOR()},
	{ATTR_VENDOR()},
	{ATTR_VENDOR()},
	{ATTR_VENDOR()},
	{ATTR_VENDOR()},
	{ATTR_VENDOR()},
	{ATTR_VENDOR()},
	{ATTR_VENDOR()},
	{ATTR_VENDOR()},
	{ATTR_VENDOR()},
	{ATTR_VENDOR()},
	{ATTR_VENDOR()},
	{ATTR_VENDOR()},
	{ATTR_VENDOR()},
	{ATTR_VENDOR()},
	{ATTR_VENDOR()},
	{ATTR_VENDOR()},
	{ATTR_VENDOR()},
	{ATTR_VENDOR()},
	{ATTR_VENDOR()},
	{ATTR_VENDOR()},
	{ATTR_VENDOR()},
	{ATTR_VENDOR()},
	{ATTR_VENDOR()},
	{ATTR_VENDOR()},
	{ATTR_VENDOR()},
	{ATTR_VENDOR()},
	{ATTR_VENDOR()},
	{ATTR_VENDOR()},
	{ATTR_VENDOR()},
	{ATTR_VENDOR()},
	{ATTR_VENDOR()},
	{ATTR_VENDOR()},
	{ATTR_VENDOR()},
	{ATTR_VENDOR()},
	{ATTR_VENDOR()},
	{ATTR_VENDOR()},
	{ATTR_VENDOR()},
	{ATTR_VENDOR()},
	{ATTR_VENDOR()},
	{ATTR_VENDOR()},
	{ATTR_VENDOR()},
	{ATTR_VENDOR()},
	{ATTR_VENDOR()}
};

struct flag_fields ufs_flags[] = {
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
	{FLAG_RSRV()},
	{"fPermanentlyDisableFw", (URD|UWRT), (READ_NRML|WRITE_ONCE), DEV},
	{FLAG_RSRV()},
/*D*/	{FLAG_RSRV()},
/*E*/	{"fWriteBoosterEn", (URD|UWRT), (READ_NRML|WRITE_VLT), DEV | ARRAY},
/*F*/	{"fWBFlushEn", (URD|UWRT), (READ_NRML|WRITE_VLT), DEV | ARRAY},
/*10h*/ {"fWBFlushDuringHibernate", (URD|UWRT), (READ_NRML|WRITE_VLT),
		DEV | ARRAY},
/*11h*/ {"fHPBReset", (URD|UWRT), (READ_NRML|SET_ONLY), DEV},
/*12h*/ {"fHPBEn", (URD|UWRT), (READ_NRML|WRITE_PRSIST), DEV},
	{FLAG_RSRV()},
	{FLAG_RSRV()},
	{FLAG_RSRV()},
	{FLAG_RSRV()},
	{FLAG_RSRV()},
	{FLAG_RSRV()},
	{FLAG_RSRV()},
	{FLAG_RSRV()},
	{FLAG_RSRV()},
	{FLAG_RSRV()},
	{FLAG_RSRV()},
	{FLAG_RSRV()},
	{FLAG_RSRV()},
	{FLAG_RSRV()},
	{FLAG_RSRV()},
	{FLAG_RSRV()},
	{FLAG_RSRV()},
	{FLAG_RSRV()},
	{FLAG_RSRV()},
	{FLAG_RSRV()},
	{FLAG_RSRV()},
	{FLAG_RSRV()},
	{FLAG_RSRV()},
	{FLAG_RSRV()},
	{FLAG_RSRV()},
	{FLAG_RSRV()},
	{FLAG_RSRV()},
	{FLAG_RSRV()},
	{FLAG_RSRV()},
	{FLAG_RSRV()},
	{FLAG_RSRV()},
	{FLAG_RSRV()},
	{FLAG_RSRV()},
	{FLAG_RSRV()},
	{FLAG_RSRV()},
	{FLAG_RSRV()},
	{FLAG_RSRV()},
	{FLAG_RSRV()},
	{FLAG_RSRV()},
	{FLAG_RSRV()},
	{FLAG_RSRV()},
	{FLAG_RSRV()},
	{FLAG_RSRV()},
	{FLAG_RSRV()},
	{FLAG_RSRV()},
	{FLAG_RSRV()},
	{FLAG_RSRV()},
	{FLAG_RSRV()},
	{FLAG_RSRV()},
	{FLAG_RSRV()},
	{FLAG_RSRV()},
	{FLAG_RSRV()},
	{FLAG_RSRV()},
	{FLAG_RSRV()},
	{FLAG_RSRV()},
	{FLAG_RSRV()},
	{FLAG_RSRV()},
	{FLAG_RSRV()},
	{FLAG_RSRV()},
	{FLAG_RSRV()},
	{FLAG_RSRV()},
	{FLAG_RSRV()},
	{FLAG_RSRV()},
	{FLAG_RSRV()},
	{FLAG_RSRV()},
	{FLAG_RSRV()},
	{FLAG_RSRV()},
	{FLAG_RSRV()},
	{FLAG_RSRV()},
	{FLAG_RSRV()},
	{FLAG_RSRV()},
	{FLAG_RSRV()},
	{FLAG_RSRV()},
	{FLAG_RSRV()},
	{FLAG_RSRV()},
	{FLAG_RSRV()},
	{FLAG_RSRV()},
	{FLAG_RSRV()},
	{FLAG_RSRV()},
	{FLAG_RSRV()},
	{FLAG_RSRV()},
	{FLAG_RSRV()},
	{FLAG_RSRV()},
	{FLAG_RSRV()},
	{FLAG_RSRV()},
	{FLAG_RSRV()},
	{FLAG_RSRV()},
	{FLAG_RSRV()},
	{FLAG_RSRV()},
	{FLAG_RSRV()},
	{FLAG_RSRV()},
	{FLAG_RSRV()},
	{FLAG_RSRV()},
	{FLAG_RSRV()},
	{FLAG_RSRV()},
	{FLAG_RSRV()},
	{FLAG_RSRV()},
	{FLAG_RSRV()},
	{FLAG_RSRV()},
	{FLAG_RSRV()},
	{FLAG_RSRV()},
	{FLAG_RSRV()},
	{FLAG_RSRV()},
	{FLAG_RSRV()},
	{FLAG_RSRV()},
	{FLAG_RSRV()},
	{FLAG_RSRV()},
	{FLAG_RSRV()},
	{FLAG_RSRV()},
	{FLAG_VENDOR()},
	{FLAG_VENDOR()},
	{FLAG_VENDOR()},
	{FLAG_VENDOR()},
	{FLAG_VENDOR()},
	{FLAG_VENDOR()},
	{FLAG_VENDOR()},
	{FLAG_VENDOR()},
	{FLAG_VENDOR()},
	{FLAG_VENDOR()},
	{FLAG_VENDOR()},
	{FLAG_VENDOR()},
	{FLAG_VENDOR()},
	{FLAG_VENDOR()},
	{FLAG_VENDOR()},
	{FLAG_VENDOR()},
	{FLAG_VENDOR()},
	{FLAG_VENDOR()},
	{FLAG_VENDOR()},
	{FLAG_VENDOR()},
	{FLAG_VENDOR()},
	{FLAG_VENDOR()},
	{FLAG_VENDOR()},
	{FLAG_VENDOR()},
	{FLAG_VENDOR()},
	{FLAG_VENDOR()},
	{FLAG_VENDOR()},
	{FLAG_VENDOR()},
	{FLAG_VENDOR()},
	{FLAG_VENDOR()},
	{FLAG_VENDOR()},
	{FLAG_VENDOR()},
	{FLAG_VENDOR()},
	{FLAG_VENDOR()},
	{FLAG_VENDOR()},
	{FLAG_VENDOR()},
	{FLAG_VENDOR()},
	{FLAG_VENDOR()},
	{FLAG_VENDOR()},
	{FLAG_VENDOR()},
	{FLAG_VENDOR()},
	{FLAG_VENDOR()},
	{FLAG_VENDOR()},
	{FLAG_VENDOR()},
	{FLAG_VENDOR()},
	{FLAG_VENDOR()},
	{FLAG_VENDOR()},
	{FLAG_VENDOR()},
	{FLAG_VENDOR()},
	{FLAG_VENDOR()},
	{FLAG_VENDOR()},
	{FLAG_VENDOR()},
	{FLAG_VENDOR()},
	{FLAG_VENDOR()},
	{FLAG_VENDOR()},
	{FLAG_VENDOR()},
	{FLAG_VENDOR()},
	{FLAG_VENDOR()},
	{FLAG_VENDOR()},
	{FLAG_VENDOR()},
	{FLAG_VENDOR()},
	{FLAG_VENDOR()},
	{FLAG_VENDOR()},
	{FLAG_VENDOR()},
	{FLAG_VENDOR()},
	{FLAG_VENDOR()},
	{FLAG_VENDOR()},
	{FLAG_VENDOR()},
	{FLAG_VENDOR()},
	{FLAG_VENDOR()},
	{FLAG_VENDOR()},
	{FLAG_VENDOR()},
	{FLAG_VENDOR()},
	{FLAG_VENDOR()},
	{FLAG_VENDOR()},
	{FLAG_VENDOR()},
	{FLAG_VENDOR()},
	{FLAG_VENDOR()},
	{FLAG_VENDOR()},
	{FLAG_VENDOR()},
	{FLAG_VENDOR()},
	{FLAG_VENDOR()},
	{FLAG_VENDOR()},
	{FLAG_VENDOR()},
	{FLAG_VENDOR()},
	{FLAG_VENDOR()},
	{FLAG_VENDOR()},
	{FLAG_VENDOR()},
	{FLAG_VENDOR()},
	{FLAG_VENDOR()},
	{FLAG_VENDOR()},
	{FLAG_VENDOR()},
	{FLAG_VENDOR()},
	{FLAG_VENDOR()},
	{FLAG_VENDOR()},
	{FLAG_VENDOR()},
	{FLAG_VENDOR()},
	{FLAG_VENDOR()},
	{FLAG_VENDOR()},
	{FLAG_VENDOR()},
	{FLAG_VENDOR()},
	{FLAG_VENDOR()},
	{FLAG_VENDOR()},
	{FLAG_VENDOR()},
	{FLAG_VENDOR()},
	{FLAG_VENDOR()},
	{FLAG_VENDOR()},
	{FLAG_VENDOR()},
	{FLAG_VENDOR()},
	{FLAG_VENDOR()},
	{FLAG_VENDOR()},
	{FLAG_VENDOR()},
	{FLAG_VENDOR()},
	{FLAG_VENDOR()},
	{FLAG_VENDOR()},
	{FLAG_VENDOR()},
	{FLAG_VENDOR()},
	{FLAG_VENDOR()},
	{FLAG_VENDOR()},
	{FLAG_VENDOR()},
	{FLAG_VENDOR()},
	{FLAG_VENDOR()},
	{FLAG_VENDOR()},
	{FLAG_VENDOR()},
	{FLAG_VENDOR()},
	{FLAG_VENDOR()},
	{FLAG_VENDOR()}
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

static const char *const desc_text[] = {
	"Device",
	"Config",
	"Unit",
	"RFU0",
	"Interconnect",
	"String",
	"RFU1",
	"Geometry",
	"Power",
	"Health"
};

static int do_unit_desc(int fd, __u8 lun, char *data_file);
static int do_power_desc(int fd, char *data_file);
static int do_conf_desc(int fd, __u8 opt, __u8 index, char *data_file);
static int do_string_desc(int fd, char *str_data, __u8 idn, __u8 opr,
			  __u8 index, char *data_file);
static int do_write_desc(int fd, struct ufs_bsg_request *bsg_req,
			 struct ufs_bsg_reply *bsg_rsp, __u8 idn, __u8 index,
			 __u16 desc_buf_len, __u8 *data_buf);
static void query_response_error(__u8 opcode, __u8 idn);
static int find_bsg_device(char *path, int *counter);

int do_read_desc(int fd, struct ufs_bsg_request *bsg_req,
		 struct ufs_bsg_reply *bsg_rsp, __u8 idn, __u8 index,
		 __u16 desc_buf_len, __u8 *data_buf);

int do_query_rq(int fd, struct ufs_bsg_request *bsg_req,
		struct ufs_bsg_reply *bsg_rsp, __u8 query_req_func,
		__u8 opcode, __u8 idn, __u8 index, __u8 sel,
		__u16 req_buf_len, __u16 res_buf_len, __u8 *data_buf);


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

static void print_vendor_info(__u8 *desc_buf, int len)
{
	int i;

	if (!desc_buf)
		return;

	for (i = 0 ; i < len; i++) {
		if (!(i%16))
			printf("\t\n");
		printf("0x%02x ", desc_buf[i]);
	}
	printf("\n");
}

static void print_descriptors_json(__u8 *desc_buf,
				   struct desc_field_offset *desc_array,
				   int arr_size)
{
	int i;
	struct desc_field_offset *tmp;
	char str_buf[STR_BUF_LEN];
	int offset = 0;

	printf("%s\n", "{");

	for (i = 0; offset < arr_size; ++i) {
		tmp = &desc_array[i];
		offset = tmp->offset + tmp->width_in_bytes;

		if (tmp->width_in_bytes == BYTE) {
			printf("%c%s%c:%d,\n", '"', tmp->name, '"',
			       desc_buf[tmp->offset]);
		} else if (tmp->width_in_bytes == WORD) {
			printf("%c%s%c:%d,\n", '"', tmp->name, '"',
			       be16toh(*(__u16 *)&desc_buf[tmp->offset]));
		} else if (tmp->width_in_bytes == DWORD) {
			printf("%c%s%c:%d,\n", '"', tmp->name, '"',
			       be32toh(*(__u32 *)&desc_buf[tmp->offset]));
		} else if (tmp->width_in_bytes == DDWORD) {
			printf("%c%s%c:%ld,\n", '"', tmp->name, '"',
			       be64toh(*(__u64 *)&desc_buf[tmp->offset]));
		} else if ((tmp->width_in_bytes > DDWORD) &&
				tmp->width_in_bytes < STR_BUF_LEN) {
			if (!strcmp(tmp->name, "VendorPropInfo")) {
				printf("%c%s%c:", '"', tmp->name, '"');
				print_vendor_info(&desc_buf[tmp->offset],
						  tmp->width_in_bytes);
			} else {
				memset(str_buf, 0, STR_BUF_LEN);
				memcpy(str_buf, &desc_buf[tmp->offset],
				       tmp->width_in_bytes);
				printf("%c%s%c:%s,\n", '"', tmp->name, '"',
				       str_buf);
			}
		} else {
			printf("Err %s[Byte offset 0x%x] Wrong Width = %d\n",
			       tmp->name, tmp->offset, tmp->width_in_bytes);
		}
	}

	printf("%s\n", "}");
}

static void print_descriptors_raw(__u8 *desc_buf, int arr_size)
{
	int i;

	for (i = 0; i < arr_size; i++) {
		printf("%02x ", desc_buf[i]);
		if ((i + 1) % 16 == 0)
			printf("\n");
	}
	printf("\n");
}

static void print_descriptors_verbose(char *desc_str, __u8 *desc_buf,
				      struct desc_field_offset *desc_array,
				      int arr_size)
{
	int i;
	struct desc_field_offset *tmp;
	char str_buf[STR_BUF_LEN];
	int offset = 0;

	for (i = 0; offset < arr_size; ++i) {
		tmp = &desc_array[i];
		offset = tmp->offset + tmp->width_in_bytes;

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
			if (!strcmp(tmp->name, "VendorPropInfo")) {
				printf("%s [Byte offset 0x%x]: %s =\n",
					desc_str,
					tmp->offset,
					tmp->name);
				print_vendor_info(&desc_buf[tmp->offset],
						  tmp->width_in_bytes);
			} else {
				memset(str_buf, 0, STR_BUF_LEN);
				memcpy(str_buf, &desc_buf[tmp->offset],
					tmp->width_in_bytes);
				printf("%s [Byte offset 0x%x]: %s = %s\n",
					desc_str,
					tmp->offset, tmp->name, str_buf);
			}
		} else {
			printf("%s [Byte offset 0x%x]: %s Wrong Width = %d",
				desc_str, tmp->offset, tmp->name,
				tmp->width_in_bytes);
		}
	}
}

static void print_descriptors(char *desc_str, __u8 *desc_buf,
			      struct desc_field_offset *desc_array,
			      int arr_size)
{
	switch (gl_pr_type) {
	case JSON:
		print_descriptors_json(desc_buf, desc_array, arr_size);
		break;
	case RAW_VALUE:
		print_descriptors_raw(desc_buf, arr_size);
		break;
	default:
		print_descriptors_verbose(desc_str, desc_buf, desc_array,
					  arr_size);
	}
}

static void print_attribute_verbose(struct attr_fields *attr, __u8 *attr_buffer)
{
	if (!attr)
		printf("%-26s := 0x%08x\n", "Attribute value",
		       *(__u32 *)attr_buffer);
	else if (attr->width_in_bytes == BYTE)
		printf("%-26s := 0x%02x\n", attr->name, attr_buffer[0]);
	else if (attr->width_in_bytes == WORD)
		printf("%-26s := 0x%04x\n", attr->name, *(__u16 *)attr_buffer);
	else if (attr->width_in_bytes == DWORD)
		printf("%-26s := 0x%08x\n", attr->name, *(__u32 *)attr_buffer);
	else
		printf("%-26s := 0x%llx\n", attr->name,
			*(__u64 *)attr_buffer);
}

static void print_attribute_raw(struct attr_fields *attr, __u8 *attr_buffer)
{
	if (!attr)
		printf("0x%08x\n", *(__u32 *)attr_buffer);
	else if (attr->width_in_bytes == BYTE)
		printf("0x%02x\n", attr_buffer[0]);
	else if (attr->width_in_bytes == WORD)
		printf("0x%04x\n", *(__u16 *)attr_buffer);
	else if (attr->width_in_bytes == DWORD)
		printf("0x%08x\n", *(__u32 *)attr_buffer);
	else
		printf("0x%llx\n", *(__u64 *)attr_buffer);
}

static void print_attribute_json(struct attr_fields *attr, __u8 *attr_buffer)
{
	printf("{\n");

	if (!attr)
		printf("%c%s%c:%d\n", '"', "Attribute value", '"',
		       *(__u32 *)attr_buffer);
	else if (attr->width_in_bytes == BYTE)
		printf("%c%s%c:%d\n", '"', attr->name, '"', attr_buffer[0]);
	else if (attr->width_in_bytes == WORD)
		printf("%c%s%c:%d\n", '"', attr->name, '"',
		       *(__u16 *)attr_buffer);
	else if (attr->width_in_bytes == DWORD)
		printf("%c%s%c:%d\n", '"', attr->name, '"',
		       *(__u32 *)attr_buffer);
	else
		printf("%c%s%c:%llu\n", '"', attr->name, '"',
		       *(__u64 *)attr_buffer);

	printf("}\n");
}

static void print_attribute(struct attr_fields *attr, __u8 *attr_buffer)
{
	switch (gl_pr_type) {
	case JSON:
		print_attribute_json(attr, attr_buffer);
		break;
	case RAW_VALUE:
		print_attribute_raw(attr, attr_buffer);
		break;
	default:
		print_attribute_verbose(attr, attr_buffer);
	}
}

static void print_flag(char *name, __u8 value)
{
	switch (gl_pr_type) {
	case JSON:
		printf("%s\n", "{");
		printf("%c%s%c:%d\n", '"', name, '"', value);
		printf("%s", "}\n");
		break;
	case RAW_VALUE:
		printf("0x%02x\n", value);
		break;
	default:
		printf("%-26s := 0x%01x\n", name, value);
	}
}

static int store_data_file(char *data_file, __u8 *buf, size_t buf_size)
{
	int rc = OK;
	int data_fd = INVALID;

	data_fd = open(data_file, O_WRONLY | O_CREAT | O_TRUNC,
		       S_IRUSR | S_IWUSR);
	if (data_fd < 0) {
		perror("can't open output file");
		return ERROR;
	}

	rc = write(data_fd, buf, buf_size);

	return rc;
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

	print_error("%s, for idn 0x%02x",
		    query_err_status[query_response_inx].name, idn);
}

static int do_unit_desc(int fd, __u8 lun, char *data_file)
{
	struct ufs_bsg_request bsg_req = {0};
	struct ufs_bsg_reply bsg_rsp = {0};
	__u8 data_buf[QUERY_DESC_MAX_SIZE] = {0};
	int rc = 0;

	rc = do_read_desc(fd, &bsg_req, &bsg_rsp, QUERY_DESC_IDN_UNIT, lun,
			  QUERY_DESC_MAX_SIZE, data_buf);
	if (rc) {
		if (rc == ERROR)
			print_error("Could not read unit descriptor");
		goto out;
	}

	if (lun == 0xc4)
		print_descriptors("RPMB LUN Descriptor", data_buf,
				device_unit_rpmb_desc_field_name, data_buf[0]);
	else
		print_descriptors("LUN Descriptor", data_buf,
				device_unit_desc_field_name, data_buf[0]);
	if (data_file) {
		rc = store_data_file(data_file, data_buf, data_buf[0]);
		if (rc < 0) {
			print_error("Could not write Unit desc data");
			rc = ERROR;
			goto out;
		}
		printf("Unit Descriptor was written into %s file\n", data_file);
	}

out:
	return rc;
}

static int do_interconnect_desc(int fd, char *data_file)
{
	struct ufs_bsg_request bsg_req = {0};
	struct ufs_bsg_reply bsg_rsp = {0};
	__u8 data_buf[QUERY_DESC_MAX_SIZE] = {0};
	int rc = 0;

	rc = do_read_desc(fd, &bsg_req, &bsg_rsp, QUERY_DESC_IDN_INTERCONNECT,
			  0, QUERY_DESC_MAX_SIZE, data_buf);
	if (rc) {
		if (rc == ERROR)
			print_error("Could not read interconnect descriptor");
		goto out;
	}

	print_descriptors("Interconnect Descriptor", data_buf,
			  device_interconnect_desc_conf_field_name,
			  data_buf[0]);

	if (data_file) {
		rc = store_data_file(data_file, data_buf, data_buf[0]);
		if (rc < 0) {
			print_error("Could not write geometry desc data");
			rc = ERROR;
			goto out;
		}
		printf("Interconnect Descriptor was written into %s file\n",
		       data_file);
	}
out:
	return rc;
}

static int do_geo_desc(int fd, char *data_file)
{
	struct ufs_bsg_request bsg_req = {0};
	struct ufs_bsg_reply bsg_rsp = {0};
	__u8 data_buf[QUERY_DESC_MAX_SIZE] = {0};
	int rc = 0;

	rc = do_read_desc(fd, &bsg_req, &bsg_rsp, QUERY_DESC_IDN_GEOMETRY, 0,
			  QUERY_DESC_MAX_SIZE, data_buf);
	if (rc) {
		if (rc == ERROR)
			print_error("Could not read geometry descriptor");
		goto out;
	}

	print_descriptors("Geometry Descriptor", data_buf,
			  device_geo_desc_conf_field_name, data_buf[0]);

	if (data_file) {
		rc = store_data_file(data_file, data_buf, data_buf[0]);
		if (rc < 0) {
			print_error("Could not write geometry desc data");
			rc = ERROR;
			goto out;
		}
		printf("Geometry Descriptor was written into %s file\n",
		       data_file);
	}

out:
	return rc;
}

static int do_power_desc(int fd, char *data_file)
{
	struct ufs_bsg_request bsg_req = {0};
	struct ufs_bsg_reply bsg_rsp = {0};
	__u8 data_buf[QUERY_DESC_MAX_SIZE] = {0};
	int rc = 0;

	rc = do_read_desc(fd, &bsg_req, &bsg_rsp,
			  QUERY_DESC_IDN_POWER, 0, QUERY_DESC_MAX_SIZE,
			  data_buf);
	if (rc) {
		if (rc == ERROR)
			print_error("Could not read power descriptor");
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
	if (data_file) {
		rc = store_data_file(data_file, data_buf, data_buf[0]);
		if (rc < 0) {
			print_error("Could not write power desc data");
			rc = ERROR;
			goto out;
		}
		printf("Power Descriptor was written into %s file\n",
		       data_file);
	}

out:
	return rc;
}

static int do_health_desc(int fd, char *data_file)
{
	struct ufs_bsg_request bsg_req = {0};
	struct ufs_bsg_reply bsg_rsp = {0};
	__u8 data_buf[QUERY_DESC_MAX_SIZE] = {0};
	int rc = 0;

	rc = do_read_desc(fd, &bsg_req, &bsg_rsp, QUERY_DESC_IDN_HEALTH, 0,
			  QUERY_DESC_MAX_SIZE, data_buf);
	if (rc) {
		if (rc == ERROR)
			print_error("Could not read device health descriptor");
		goto out;
	}

	print_descriptors("Device Health Descriptor:", data_buf,
			  device_health_desc_conf_field_name, data_buf[0]);
	if (data_file) {
		rc = store_data_file(data_file, data_buf, data_buf[0]);
		if (rc < 0) {
			print_error("Could not write string desc data");
			rc = ERROR;
			goto out;
		}
		printf("Device Health Descriptor was written into %s file\n",
		       data_file);
	}

out:
	return rc;
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
			  __u8 index, char *data_file)
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
		if (data_file) {
			rc = store_data_file(data_file, data_buf,
					     bsg_rsp.reply_payload_rcv_len);
			if (rc < 0) {
				print_error("Could not write string desc data");
				rc = ERROR;
				goto out;
			}
			printf("String Descriptor was written into %s file\n",
			       data_file);
		}
	}
out:
	return rc;
}

static int do_conf_desc(int fd, __u8 opt, __u8 index, char *data_file)
{
	int rc = OK;
	int file_size;
	struct ufs_bsg_request bsg_req = {0};
	struct ufs_bsg_reply bsg_rsp = {0};
	__u8 conf_desc_buf[QUERY_DESC_MAX_SIZE] = {0};
	int offset, i;
	int data_fd = INVALID;

	if (opt == WRITE) {
		data_fd = open(data_file, O_RDONLY);
		if (data_fd < 0) {
			perror("can't open input file");
			return ERROR;
		}

		file_size = lseek(data_fd, 0, SEEK_END);
		if (file_size <= 0) {
			print_error("Wrong config file");
			rc = ERROR;
			goto out;
		}
		lseek(data_fd, 0, SEEK_SET);

		rc = read(data_fd, conf_desc_buf, file_size);
		if (rc <= 0) {
			print_error("Cannot config file");
			rc = ERROR;
			goto out;
		}

		rc = do_write_desc(fd, &bsg_req, &bsg_rsp,
				QUERY_DESC_IDN_CONFIGURAION, index,
				file_size,
				conf_desc_buf);
		if (!rc)
			printf("Config Descriptor was written to device\n");
	} else {
		__u8 head_off = CONFIG_HEADER_OFFSET;
		__u8 lun_off = CONFIG_LUN_OFFSET;

		rc = do_read_desc(fd, &bsg_req, &bsg_rsp,
				QUERY_DESC_IDN_CONFIGURAION,
				index, QUERY_DESC_MAX_SIZE,
				conf_desc_buf);
		if (rc) {
			if (rc == ERROR)
				print_error("Coudn't read config descriptor");

			goto out;
		}

		if (conf_desc_buf[0] == QUERY_DESC_CONFIGURAION_MAX_SIZE_3_0) {
			head_off = CONFIG_HEADER_OFFSET_3_0;
			lun_off = CONFIG_LUN_OFFSET_3_0;
		}

		print_descriptors("Config Device Descriptor:",
			conf_desc_buf,
			device_config_desc_field_name,
			head_off);

		offset = head_off;
		for (i = 0 ; i < 8; i++) {
			if (gl_pr_type == VERBOSE)
				printf("Config %d Unit Descriptor:\n", i);
			print_descriptors("Config Descriptor:",
				conf_desc_buf + offset,
				device_config_unit_desc_field_name,
				lun_off);
			offset = offset  + lun_off;
		}
		if (data_file) {
			rc = store_data_file(data_file, conf_desc_buf,
					     conf_desc_buf[0]);
			if (rc < 0) {
				print_error("Could not write config data");
				rc = ERROR;
				goto out;
			}
			printf("Config Descriptor was written into %s file\n",
			       data_file);
		}
	}
out:
	if (data_fd != INVALID)
		close(data_fd);
	return rc;
}

static int do_fbo_desc(int fd)
{
	struct ufs_bsg_request bsg_req = {0};
	struct ufs_bsg_reply bsg_rsp = {0};
	__u8 data_buf[QUERY_DESC_MAX_SIZE] = {0};
	int rc = 0;

	rc = do_read_desc(fd, &bsg_req, &bsg_rsp, QUERY_DESC_IDN_FBO, 0,
			   QUERY_DESC_MAX_SIZE, data_buf);
	if (rc) {
		if (rc == ERROR)
			print_error("Could not read FBO descriptor");

		goto out;
	}

	print_descriptors("FBO Descriptor:", data_buf,
			  device_fbo_desc_field_name, data_buf[0]);
out:
	return rc;
}

int do_vendor_desc(int fd, __u8 idn, char *data_file)
{
	struct ufs_bsg_request bsg_req = {0};
	struct ufs_bsg_reply bsg_rsp = {0};
	__u8 data_buf[QUERY_DESC_MAX_SIZE] = {0};
	int rc = 0;

	rc = do_read_desc(fd, &bsg_req, &bsg_rsp,
			  idn, 0, QUERY_DESC_MAX_SIZE, data_buf);
	if (rc) {
		if (rc == ERROR)
			print_error("Could not read the descriptor");
		goto out;
	}

	gl_pr_type = RAW_VALUE;
	print_descriptors("Reserved/Vendor Descriptor", data_buf, 0,
			   data_buf[0]);

	if (data_file) {
		rc = store_data_file(data_file, data_buf, data_buf[0]);
		if (rc < 0) {
			print_error("Could not write string desc data");
			rc = ERROR;
			goto out;
		}
		printf("Reserved/Vendor Descriptor was written into %s file\n",
		       data_file);
	}

out:
	return rc;
}

static int find_bsg_device(char* path, int *counter) {
	struct dirent *files;
	DIR* dir;
	int rc = OK;

	dir = opendir(path);
	if (dir == NULL){
		perror("Directory cannot be opened!");
		return ERROR;
	}
	while ((files = readdir(dir)) != NULL) {
		if (strstr(files->d_name, "ufs-bsg") != 0) {
			printf("%s/%s\n", path, files->d_name);
			(*counter)++;
		}
		if (files->d_type == DT_DIR) {
			if ((strcmp(files->d_name, ".") != 0) &&
			    (strcmp(files->d_name, "..") != 0)) {
				char *full_path = (char *)malloc(strlen(path) +
						   strlen(files->d_name) + 1);
				sprintf(full_path, "%s/%s",
					path, files->d_name);
				rc = find_bsg_device(full_path, counter);
				free(full_path);
			}
		}
	}
	closedir(dir);
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

static int check_read_desc_size(__u8 idn, __u8 *data_buf)
{
	bool unoff = false;
	int rc = OK;

	switch (idn) {
	case QUERY_DESC_IDN_DEVICE:
		if ((data_buf[0] != QUERY_DESC_DEVICE_MAX_SIZE) &&
			(data_buf[0] != QUERY_DESC_DEVICE_MAX_SIZE_3_0))
			unoff = true;
		break;
	case QUERY_DESC_IDN_CONFIGURAION:
		if ((data_buf[0] != QUERY_DESC_CONFIGURAION_MAX_SIZE) &&
			(data_buf[0] != QUERY_DESC_CONFIGURAION_MAX_SIZE_3_0))
			unoff = true;
		break;
	case QUERY_DESC_IDN_UNIT:
		if ((data_buf[0] != QUERY_DESC_UNIT_MAX_SIZE) &&
			(data_buf[0] != QUERY_DESC_UNIT_MAX_SIZE_3_0))
			unoff = true;
		break;
	case QUERY_DESC_IDN_INTERCONNECT:
		if (data_buf[0] != QUERY_DESC_INTERCONNECT_MAX_SIZE)
			unoff = true;
		break;
	case QUERY_DESC_IDN_GEOMETRY:
		if ((data_buf[0] != QUERY_DESC_GEOMETRY_MAX_SIZE) &&
			(data_buf[0] != QUERY_DESC_GEOMETRY_MAX_SIZE_3_0))
			unoff = true;
		break;
	case QUERY_DESC_IDN_POWER:
		if (data_buf[0] != QUERY_DESC_POWER_MAX_SIZE)
			unoff = true;
		break;
	case QUERY_DESC_IDN_HEALTH:
		if ((data_buf[0] != QUERY_DESC_HEALTH_MAX_SIZE) &&
			(data_buf[0] != QUERY_DESC_HEALTH_MAX_SIZE_2_1))
			unoff = true;
	break;
	case QUERY_DESC_IDN_FBO:
		if (data_buf[0] != QUERY_DESC_FBO_MAX_SIZE)
			unoff = true;
	break;
	}

	if (unoff) {
		int file_status;

		rc = WARNING;
		print_warn("Unofficial %s desc size, len = 0x%x",
			    (char *)desc_text[idn], data_buf[0]);
		file_status = write_file("unofficial.dat", data_buf,
					 data_buf[0]);
		if (!file_status)
			printf("\nunofficial.dat raw data file was created\n");
	}

	return rc;
}

void desc_help(char *tool_name)
{
	printf("\n Descriptor command usage:\n");
	printf("\n\t%s desc [-t] <descriptor idn> [-a|-r|-w] <data> [-p] "
		"<device_path> \n", tool_name);
	printf("\n\t-t\t\t description type idn\n"
		"\t\t\t Available description types based on UFS ver 4.0 :\n"
		"\t\t\t 0:\tDevice\n"
		"\t\t\t 1:\tConfiguration\n"
		"\t\t\t 2:\tUnit\n"
		"\t\t\t 3:\tRFU\n"
		"\t\t\t 4:\tInterconnect\n"
		"\t\t\t 5:\tString\n"
		"\t\t\t 6:\tRFU\n"
		"\t\t\t 7:\tGeometry\n"
		"\t\t\t 8:\tPower\n"
		"\t\t\t 9:\tDevice Health\n"
		"\t\t\t 10:\tFBO\n"
		"\t\t\t 11..255: RFU\n");
	printf("\n\t-r\t\t read operation (default) for readable descriptors\n");
	printf("\n\t-w\t\t write operation , for writable descriptors\n");
	printf("\t\t\t Set the input configuration file after -w opt\n");
	printf("\t\t\t for Configuration descriptor\n");
	printf("\t\t\t Set the input string after -w opt\n");
	printf("\t\t\t for String descriptor\n");
	printf("\n\t-i\t\t Set index parameter(default = 0)\n");
	printf("\n\t-s\t\t Set selector parameter(default = 0)\n");
	printf("\n\t-D/--output_file Set descriptor file output path\n");
	printf("\n\t-P/--output_mode Set print output [raw, json, verbose (default)]\n");
	printf("\n\t-p\t\t path to ufs bsg device\n");
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
		" UFS ver 4.0 :\n");

	while (current_att < QUERY_ATTR_IDN_MAX) {
		printf("\t\t\t %-3d: %-25s %s\n",
			current_att,
			ufs_attrs[current_att].name,
			access_type_string(current_att, ATTR_TYPE,
			access_string));
		current_att++;
		memset(access_string, 0, 100);
	}

	printf("\n\t-a\t\t read and print all readable attributes for the device\n");
	printf("\n\t-r\t\t read operation (default), for readable attribute(s)\n");
	printf("\n\t-w\t\t write operation (with hex data), for writable attribute\n");
	printf("\n\t-i\t\t Set index parameter(default = 0)\n");
	printf("\n\t-s\t\t Set selector parameter(default = 0)\n");
	printf("\n\t-p\t\t path to ufs bsg device\n");
	printf("\n\t-P/--output_mode Set print output [raw, json, verbose (default)]\n");
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
		"\t\t Available flags and its access, based on UFS ver 4.0 :\n");

	while (current_flag < QUERY_FLAG_IDN_MAX) {
		printf("\t\t\t %-3d: %-25s %s\n", current_flag,
		       ufs_flags[current_flag].name,
		       access_type_string(current_flag, FLAG_TYPE,
					   access_string));
		current_flag++;
		memset(access_string, 0, 100);
	}
	printf("\n\t-a\t\t read and print all readable flags for the device\n");
	printf("\n\t-r\t\t read operation (default), for readable flag(s)\n");
	printf("\n\t-e\t\t set flag operation\n");
	printf("\n\t-c\t\t clear/reset flag operation\n");
	printf("\n\t-o\t\t toggle flag operation\n");
	printf("\n\t-i\t\t Set index parameter(default = 0)\n");
	printf("\n\t-s\t\t Set selector parameter(default = 0)\n");
	printf("\n\t-p\t\t path to ufs bsg device\n");
	printf("\n\t-P/--output_mode Set print output [raw, json, verbose (default)]\n");
	printf("\n\tExample - Read the bkops operation flag\n"
		"\t\t%s fl -t 4 -p /dev/ufs-bsg\n", tool_name);
}

void ufs_spec_ver_help(char *tool_name)
{
	printf("\n Get UFS spec version usage:\n");
	printf("\n\t%s spec_version [-p] <device_path> \n", tool_name);
	printf("\n\t-p\tpath to ufs bsg device\n");
}

void ufs_bsg_list_help(char *tool_name)
{
	printf("\n Find UFS BSG device list usage:\n");
	printf("\n\t%s list_bsg\n", tool_name);
}

int do_device_desc(int fd, __u8 *desc_buff, char *data_file)
{
	struct ufs_bsg_request bsg_req = {0};
	struct ufs_bsg_reply bsg_rsp = {0};
	__u8 data_buf[QUERY_DESC_MAX_SIZE] = {0};
	int rc = 0;

	rc = do_read_desc(fd, &bsg_req, &bsg_rsp,
			  QUERY_DESC_IDN_DEVICE, 0,
			  QUERY_DESC_MAX_SIZE, data_buf);
	if (rc) {
		if (rc == ERROR)
			print_error("Could not read device descriptor");
		goto out;
	}
	if (!desc_buff)
		print_descriptors("Device Descriptor", data_buf,
				  device_desc_field_name, data_buf[0]);
	else
		memcpy(desc_buff, data_buf, data_buf[0]);

	if (data_file) {
		rc = store_data_file(data_file, data_buf, data_buf[0]);
		if (rc < 0) {
			print_error("Could not write string desc data");
			rc = ERROR;
			goto out;
		}
		printf("Device Descriptor was written into %s file\n",
		       data_file);
	}

out:
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
		perror("Device open");
		return ERROR;
	}

	if (opt->opr == READ_ALL) {
		if (do_device_desc(fd, 0, 0) || do_unit_desc(fd, 0, 0) ||
		    do_interconnect_desc(fd, 0) || do_geo_desc(fd, 0) ||
		    do_power_desc(fd, 0) || do_health_desc(fd, 0) ||
		    do_conf_desc(fd, READ, 0, 0))
			rc = ERROR;
		goto out;
	}

	switch (opt->idn) {
	case QUERY_DESC_IDN_DEVICE:
		rc = do_device_desc(fd, 0, opt->data);
		break;
	case QUERY_DESC_IDN_CONFIGURAION:
		rc = do_conf_desc(fd, opt->opr, opt->index, (char *)opt->data);
		break;
	case QUERY_DESC_IDN_UNIT:
		rc = do_unit_desc(fd, opt->index, opt->data);
		break;
	case QUERY_DESC_IDN_GEOMETRY:
		rc = do_geo_desc(fd, opt->data);
		break;
	case QUERY_DESC_IDN_POWER:
		rc = do_power_desc(fd, opt->data);
		break;
	case QUERY_DESC_IDN_STRING:
		rc = do_string_desc(fd, (char *)opt->data, opt->idn, opt->opr,
				    opt->index, opt->data);
		break;
	case QUERY_DESC_IDN_HEALTH:
		rc = do_health_desc(fd, opt->data);
		break;
	case QUERY_DESC_IDN_INTERCONNECT:
		rc = do_interconnect_desc(fd, opt->data);
		break;
	case QUERY_DESC_IDN_FBO:
		rc = do_fbo_desc(fd);
		break;
	default:
		if (opt->idn > QUERY_DESC_IDN_MAX) {
			print_error("Unsupported Descriptor type %d", opt->idn);
			rc = -EINVAL;
		} else {
			rc = do_vendor_desc(fd, opt->idn, opt->data);
		}
		break;
	}

out:
	close(fd);
	return rc;
}

int do_get_ufs_spec_ver(struct tool_options *opt)
{
	int fd;
	int rc = OK;
	int oflag = O_RDWR;
	__u8 dev_desc[QUERY_DESC_DEVICE_MAX_SIZE] = {0};
	__u16 *ufs_spec;
	__u16 spec_value;
	__u8 maj_vers, minor_ver, vers_suf = 0;
	struct desc_field_offset *tmp = &device_desc_field_name[0x10];

	if (opt->opr == READ_ALL || opt->opr == READ)
		oflag = O_RDONLY;

	fd = open(opt->path, oflag);
	if (fd < 0) {
		perror("Device open");
		return ERROR;
	}

	rc = do_device_desc(fd, (__u8 *)&dev_desc, 0);
	if (rc != OK) {
		print_error("Could not read device descriptor in order to "
			    "get device ufs spec version\n");
	} else {
		ufs_spec = (__u16 *)&dev_desc[tmp->offset];
		spec_value = be16toh(*ufs_spec);
		maj_vers = spec_value >> 8 & 0xff;
		minor_ver = spec_value >> 4 & 0x0f;
		vers_suf = spec_value & 0x0f;
		if (vers_suf)
			printf("%d.%d%d\n", maj_vers, minor_ver, vers_suf);
		else
			printf("%d.%d\n", maj_vers, minor_ver);
	}

	close(fd);
	return rc;
}

int do_get_ufs_bsg_list(struct tool_options *opt)
{
	int rc;
	int counter = 0;

	rc = find_bsg_device("/dev", &counter);
	if (!counter)
		printf("Didn't found UFS BSG device\n");
	return rc;
}

int do_query_rq(int fd, struct ufs_bsg_request *bsg_req,
			struct ufs_bsg_reply *bsg_rsp, __u8 query_req_func,
			__u8 opcode, __u8 idn, __u8 index, __u8 sel,
			__u16 req_buf_len, __u16 res_buf_len, __u8 *data_buf)
{
	int rc = OK;
	__u8 res_code;
	__u16 len = res_buf_len;
	bool write =  false;

	if (req_buf_len > 0) {
		len = req_buf_len;
		write = true;
	}

	prepare_upiu(bsg_req, query_req_func, len, opcode, idn,
		index, sel);

	rc = send_bsg_scsi_trs(fd, bsg_req, bsg_rsp, sizeof(*bsg_req), sizeof(*bsg_rsp),
			        len, data_buf, write);

	if (rc) {
		print_error("%s: query failed, status %d idn: %d, i: %d, s: %d",
			__func__, rc, idn, index, sel);
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

int do_read_desc(int fd, struct ufs_bsg_request *bsg_req,
			struct ufs_bsg_reply *bsg_rsp, __u8 idn, __u8 index,
			__u16 desc_buf_len, __u8 *data_buf)
{
	int rc;

	rc = do_query_rq(fd, bsg_req, bsg_rsp,
			UPIU_QUERY_FUNC_STANDARD_READ_REQUEST,
			UPIU_QUERY_OPCODE_READ_DESC, idn, index, 0,
			0, desc_buf_len, data_buf);
	if (!rc)
		rc = check_read_desc_size(idn, data_buf);

	return rc;
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
		perror("Device open");
		return ERROR;
	}
	tmp = &ufs_attrs[opt->idn];

	if (opt->opr == READ_ALL) {
		att_idn = QUERY_ATTR_IDN_BOOT_LU_EN;

		while (att_idn < QUERY_ATTR_IDN_MAX) {
			tmp = &ufs_attrs[att_idn];
			if (tmp->acc_type == ACC_INVALID ||
			    tmp->acc_mode & WRITE_ONLY ||
			    !strcmp(tmp->name, "VendorSpecificAttr")) {
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
		attr_value = *(__u32 *)opt->data;
		if (opt->idn > ARRAY_SIZE(ufs_attrs) ||
		    tmp->acc_type == ACC_INVALID)
			goto skip_width_check;
		switch (tmp->width_in_bytes) {
		case BYTE:
			if (attr_value > 0xFF) {
				print_error("Wrong write data for %s attr",
					tmp->name);
				rc = ERROR;
				goto out;
			}
			break;
		case WORD:
			if (attr_value > 0xFFFF) {
				print_error("Wrong write data for %s attr",
					tmp->name);
				rc = ERROR;
				goto out;
			}
			break;
		case DWORD:
			if (attr_value > 0xFFFFFFFF) {
				print_error("Wrong write data for %s attr",
					tmp->name);
				rc = ERROR;
				goto out;
			}
			break;
		default:
			print_warn("Undefined attr %u", opt->idn);
		}
skip_width_check:
		bsg_req.upiu_req.qr.value = htobe32(attr_value);
		rc = do_query_rq(fd, &bsg_req, &bsg_rsp,
				UPIU_QUERY_FUNC_STANDARD_WRITE_REQUEST,
				UPIU_QUERY_OPCODE_WRITE_ATTR, opt->idn,
				opt->index, opt->selector, 0, 0, 0);
	} else if (opt->opr == READ) {
		if (tmp->acc_mode & WRITE_ONLY) {
			print_error("The attribute is write only");
			goto out;
		}

		rc = do_query_rq(fd, &bsg_req, &bsg_rsp,
				UPIU_QUERY_FUNC_STANDARD_READ_REQUEST,
				UPIU_QUERY_OPCODE_READ_ATTR, opt->idn,
				opt->index, opt->selector, 0, 0, 0);
		if (rc == OK) {
			attr_value = be32toh(bsg_rsp.upiu_rsp.qr.value);
			if (opt->idn > ARRAY_SIZE(ufs_attrs) ||
			    tmp->acc_type == ACC_INVALID)
				tmp = 0;
			else
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
	__u8 opcode, flag_idn, value;
	struct flag_fields *tmp;
	struct ufs_bsg_request bsg_req = {0};
	struct ufs_bsg_reply bsg_rsp = {0};
	int oflag = O_RDWR;

	if (opt->opr == READ_ALL || opt->opr == READ)
		oflag = O_RDONLY;

	fd = open(opt->path, oflag);
	if (fd < 0) {
		perror("Device open");
		return ERROR;
	}

	tmp = &ufs_flags[opt->idn];

	switch (opt->opr) {
	case READ_ALL:
		flag_idn = QUERY_FLAG_IDN_FDEVICEINIT;
		printf("UFS Device Flags:\n");
		while (flag_idn < ARRAY_SIZE(ufs_flags)) {
			tmp = &ufs_flags[flag_idn];
			if (tmp->acc_type == ACC_INVALID ||
			    tmp->acc_mode & WRITE_ONLY ||
			    !strcmp(tmp->name, "VendorSpecificFlag")) {
				flag_idn++;
				continue;
			}

			rc = do_query_rq(fd, &bsg_req, &bsg_rsp,
					UPIU_QUERY_FUNC_STANDARD_READ_REQUEST,
					UPIU_QUERY_OPCODE_READ_FLAG, flag_idn,
					opt->index, opt->selector, 0, 0, 0);
			if (rc == OK) {
				value = be32toh(bsg_rsp.upiu_rsp.qr.value) &
						0xff;
				print_flag(tmp->name, value);
			}

			memset(&bsg_rsp, 0, BSG_REPLY_SZ);
			flag_idn++;
		}
	break;
	case CLEAR_FLAG:
	case TOGGLE_FLAG:
	case SET_FLAG:
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
			print_error("The operation for flag %d failed",
				    opt->idn);
	break;
	case READ:/*Read operation */
		if (tmp->acc_mode & WRITE_ONLY) {
			print_error("The flag is write only");
			goto out;
		}

		rc = do_query_rq(fd, &bsg_req, &bsg_rsp,
				 UPIU_QUERY_FUNC_STANDARD_READ_REQUEST,
				 UPIU_QUERY_OPCODE_READ_FLAG, opt->idn,
				 opt->index, opt->selector, 0, 0, 0);
		if (rc == OK) {
			value = be32toh(bsg_rsp.upiu_rsp.qr.value) & 0xff;
			if (opt->idn < ARRAY_SIZE(ufs_flags))
				print_flag(tmp->name, value);
			else
				print_flag("Flag value", value);
		} else {
			print_error("Read for flag %d failed", opt->idn);
		}

	break;
	default:
		print_error("Unsupported operation for %s flag", tmp->name);
		rc = ERROR;
	break;
	}

out:
	close(fd);
	return rc;
}
