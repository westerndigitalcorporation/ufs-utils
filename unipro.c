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
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <ctype.h>
#include <errno.h>
#include <stdint.h>

#include "options.h"
#include "ufs.h"
#include "unipro.h"

/*PHY Adapter Layer(L1.5) */
static struct ufs_uic_attr_fields phy_adapter_attrs[] = {
	/*  PHY Adapter (gettable, settable) Common Attributes */
	{"PA_ActiveTxDataLanes", 0x1560, (GETTABLE | SETTABLE)},
	{"PA_TxTrailingClocks", 0x1564, (GETTABLE | SETTABLE)},
	{"PA_ActiveRxDataLanes", 0x1580, (GETTABLE | SETTABLE)},

	/* PHY Adapter (gettable, static) Common Attributes */
	{"PA_PHY_Type", 0x1500, (GETTABLE | STATIC)},
	{"PA_AvailTxDataLanes", 0x1520, (GETTABLE | STATIC)},
	{"PA_AvailRxDataLanes", 0x1540, (GETTABLE | STATIC)},
	{"PA_MinRxTrailingClocks", 0x1543, (GETTABLE | STATIC)},

	/* PHY Adapter (gettable, dynamic) Common Attributes */
	{"PA_TxPWRStatus", 0x1567, (GETTABLE | DYNAMIC)},
	{"PA_RxPWRStatus", 0x1582, (GETTABLE | DYNAMIC)},
	{"PA_RemoteVerInfo", 0x15A0, (GETTABLE | DYNAMIC)},

	/* PHY Adapter (gettable, settable) M-PHY-Specific Attributes */
	{"PA_TxHsG1SyncLength", 0x1552, (GETTABLE | SETTABLE)},
	{"PA_TxHsG1PrepareLength", 0x1553, (GETTABLE | SETTABLE)},
	{"PA_TxHsG2SyncLength", 0x1554, (GETTABLE | SETTABLE)},
	{"PA_TxHsG2PrepareLength", 0x1555, (GETTABLE | SETTABLE)},
	{"PA_TxHsG3SyncLength", 0x1556, (GETTABLE | SETTABLE)},
	{"PA_TxHsG3PrepareLength", 0x1557, (GETTABLE | SETTABLE)},
	{"PA_TxMk2Extension", 0x155A, (GETTABLE | SETTABLE)},
	{"PA_PeerScrambling", 0x155B, (GETTABLE | SETTABLE)},
	{"PA_TxSkip", 0x155C, (GETTABLE | SETTABLE)},
	{"PA_TxSkipPeriod", 0x155D, (GETTABLE | SETTABLE)},
	{"PA_Local_TX_LCC_Enable", 0x155E, (GETTABLE | SETTABLE)},
	{"PA_Peer_TX_LCC_Enable", 0x155F, (GETTABLE | SETTABLE)},
	{"PA_ConnectedTxDataLanes", 0x1561, (GETTABLE | SETTABLE)},
	{"PA_TxGear", 0x1568, (GETTABLE | SETTABLE)},
	{"PA_TxTermination", 0x1569, (GETTABLE | SETTABLE)},
	{"PA_HSSeries", 0x156A, (GETTABLE | SETTABLE)},
	{"PA_PWRMode", 0x1571, (GETTABLE | SETTABLE)},
	{"PA_ConnectedRxDataLanes", 0x1581, (GETTABLE | SETTABLE)},
	{"PA_RxGear", 0x1583, (GETTABLE | SETTABLE)},
	{"PA_RxTermination", 0x1584, (GETTABLE | SETTABLE)},
	{"PA_Scrambling", 0x1585, (GETTABLE | SETTABLE)},
	{"PA_MaxRxPWMGear", 0x1586, (GETTABLE | SETTABLE)},
	{"PA_MaxRxHSGear", 0x1587, (GETTABLE | SETTABLE)},
	{"PA_PACPReqTimeout", 0x1590, (GETTABLE | SETTABLE)},
	{"PA_PACPReqEoBTimeout", 0x1591, (GETTABLE | SETTABLE)},
	{"PA_LogicalLaneMap", 0x15A1, (GETTABLE | SETTABLE)},
	{"PA_SleepNoConfigTime", 0x15A2, (GETTABLE | SETTABLE)},
	{"PA_StallNoConfigTime", 0x15A3, (GETTABLE | SETTABLE)},
	{"PA_SaveConfigTime", 0x15A4, (GETTABLE | SETTABLE)},
	{"PA_RxHSUnterminationCapability", 0x15A5, (GETTABLE | SETTABLE)},
	{"PA_RxLSTerminationCapability", 0x15A6, (GETTABLE | SETTABLE)},
	{"PA_Hibern8Time", 0x15A7, (GETTABLE | SETTABLE)},
	{"PA_TActivate", 0x15A8, (GETTABLE | SETTABLE)},
	{"PA_LocalVerInfo", 0x15A9, (GETTABLE | SETTABLE)},
	{"PA_Granularity", 0x15AA, (GETTABLE | SETTABLE)},
	{"PA_MK2ExtensionGuardBand", 0x15AB, (GETTABLE | SETTABLE)},
	{"PA_PWRModeUserData", 0x15B0, (GETTABLE | SETTABLE)},
	{"PA_PACPFrameCount", 0x15C0, (GETTABLE | SETTABLE)},
	{"PA_PACPErrorCount", 0x15C1, (GETTABLE | SETTABLE)},
	{"PA_PHYTestControl", 0x15C2, (GETTABLE | SETTABLE)},
	{"PA_TxHsG4SyncLength", 0x15D0, (GETTABLE | SETTABLE)},
	{"PA_TxHsG4PrepareLength", 0x15D1, (GETTABLE | SETTABLE)},
	{"PA_PeerRxHsAdaptRefresh", 0x15D2, (GETTABLE | SETTABLE)},
	{"PA_PeerRxHsAdaptInitial", 0x15D3, (GETTABLE | SETTABLE)},
	{"PA_TxHsAdaptType", 0x15D4, (GETTABLE | SETTABLE)},
	{"PA_AdaptAfterLRSTInPA_INIT", 0x15D5, (GETTABLE | SETTABLE)},
};

/* Unipro QoS Measurement DME Attributes */
static struct ufs_uic_attr_fields dme_qos_attrs[] = {
	/* Unipro QoS Measurement DME Attributes */
	{"DME_TX_DATA_OFL", 0x5100, (GETTABLE | SETTABLE)},
	{"DME_TX_NAC_RECEIVED", 0x5101, (GETTABLE | SETTABLE)},
	{"DME_TX_QoS_COUNT", 0x5102, (GETTABLE | SETTABLE)},
	{"DME_TX_DL_LM_ERROR", 0x5103, (GETTABLE | SETTABLE)},
	{"DME_RX_DATA_OFL", 0x5110, (GETTABLE | SETTABLE)},
	{"DME_RX_CRC_ERROR", 0x5111, (GETTABLE | SETTABLE)},
	{"DME_RX_QoS_COUNT", 0x5112, (GETTABLE | SETTABLE)},
	{"DME_RX_DL_LM_ERROR", 0x5113, (GETTABLE | SETTABLE)},
	{"DME_TXRX_DATA_OFL", 0x5120, (GETTABLE | SETTABLE)},
	{"DME_TXRX_PA_INIT_REQUEST", 0x5121, (GETTABLE | SETTABLE)},
	{"DME_TXRX_QoS_COUNT", 0x5122, (GETTABLE | SETTABLE)},
	{"DME_TXRX_DL_LM_ERROR", 0x5123, (GETTABLE | SETTABLE)},
	{"DME_QoS_ENABLE", 0x5130, (GETTABLE | SETTABLE)},
	{"DME_QoS_STATUS", 0x5131, (GETTABLE | SETTABLE)},
};

/* M-TX/M-RX Capability Attributes */
static struct ufs_uic_attr_fields mipi_mphy_attrs[] = {
	/* M-PHY TX Capability Attributes */
	{"TX_HSMODE_Capability", 0x0001, (GETTABLE)},
	{"TX_HSGEAR_Capability", 0x0002, (GETTABLE)},
	{"TX_PWMG0_Capability", 0x0003, (GETTABLE)},
	{"TX_PWMGEAR_Capability", 0x0004, (GETTABLE)},
	{"TX_Amplitude_Capability", 0x0005, (GETTABLE)},
	{"TX_ExternalSYNC_Capability", 0x0006, (GETTABLE)},
	{"TX_HS_Unterminated_LINE_Drive_Capability", 0x0007, (GETTABLE)},
	{"TX_LS_Terminated_LINE_Drive_Capability", 0x0008, (GETTABLE)},
	{"TX_Min_SLEEP_NoConfig_Time_Capability", 0x0009, (GETTABLE)},
	{"TX_Min_STALL_NoConfig_Time_Capability", 0x000A, (GETTABLE)},
	{"TX_Min_SAVE_Config_Time_Capability", 0x000B, (GETTABLE)},
	{"TX_REF_CLOCK_SHARED_Capability", 0x000C, (GETTABLE)},
	{"TX_PHY_MajorMinor_Release_Capability", 0x000D, (GETTABLE)},
	{"TX_PHY_Editorial_Release_Capability", 0x000E, (GETTABLE)},
	{"TX_Hibern8Time_Capability", 0x000F, (GETTABLE)},
	{"TX_Advanced_Granularity_Capability", 0x0010, (GETTABLE)},
	{"TX_Advanced_Hibern8Time_Capability", 0x0011, (GETTABLE)},
	{"TX_HS_Equalizer_Setting_Capability", 0x0012, (GETTABLE)},

	/* M-PHY TX Configuration Attributes */
	{"TX_MODE", 0x0021, (GETTABLE | SETTABLE)},
	{"TX_HSRATE_Series", 0x0022, (GETTABLE | SETTABLE)},
	{"TX_HSGEAR", 0x0023, (GETTABLE | SETTABLE)},
	{"TX_PWMGEAR", 0x0024, (GETTABLE | SETTABLE)},
	{"TX_Amplitude", 0x0025, (GETTABLE | SETTABLE)},
	{"TX_HS_SlewRate", 0x0026, (GETTABLE | SETTABLE)},
	{"TX_SYNC_Source", 0x0027, (GETTABLE | SETTABLE)},
	{"TX_HS_SYNC_LENGTH", 0x0028, (GETTABLE | SETTABLE)},
	{"TX_HS_PREPARE_LENGTH", 0x0029, (GETTABLE | SETTABLE)},
	{"TX_LS_PREPARE_LENGTH", 0x002A, (GETTABLE | SETTABLE)},
	{"TX_HIBERN8_Control", 0x002B, (GETTABLE | SETTABLE)},
	{"TX_LCC_Enable", 0x002C, (GETTABLE | SETTABLE)},
	{"TX_PWM_BURST_Closure_Extension", 0x002D, (GETTABLE | SETTABLE)},
	{"TX_BYPASS_8B10B_Enable", 0x002E, (GETTABLE | SETTABLE)},
	{"TX_DRIVER_POLARITY", 0x002F, (GETTABLE | SETTABLE)},
	{"TX_HS_Unterminated_LINE_Drive_Enable", 0x0030, (GETTABLE | SETTABLE)},
	{"TX_LS_Terminated_LINE_Drive_Enable", 0x0031, (GETTABLE | SETTABLE)},
	{"TX_LCC_Sequencer", 0x0032, (GETTABLE | SETTABLE)},
	{"TX_Min_ActivateTime", 0x0033, (GETTABLE | SETTABLE)},
	{"TX_PWM_G6_G7_SYNC_LENGTH", 0x0034, (GETTABLE | SETTABLE)},
	{"TX_Advanced_Granularity_Step", 0x0035, (GETTABLE | SETTABLE)},
	{"TX_Advanced_Granularity", 0x0036, (GETTABLE | SETTABLE)},
	{"TX_HS_Equalizer_Setting", 0x0037, (GETTABLE | SETTABLE)},
	{"TX_Min_SLEEP_NoConfig_Time", 0x0038, (GETTABLE | SETTABLE)},
	{"TX_Min_STALL_NoConfig_Time", 0x0039, (GETTABLE | SETTABLE)},
	{"TX_HS_ADAPT_LENGTH", 0x003A, (GETTABLE | SETTABLE)},

	/*  M-TX Status Attributes */
	{"TX_FSM_State", 0x0041, (GETTABLE)},

	/* M-PHY OMC Write-only Attributes */
	{"MC_Output_Amplitude", 0x0061, (SETTABLE)},
	{"MC_HS_Unterminated_Enable", 0x0062, (SETTABLE)},
	{"MC_LS_Terminated_Enable", 0x0063, (SETTABLE)},
	{"MC_HS_Unterminated_LINE_Drive_Enable", 0x0064, (SETTABLE)},
	{"MC_LS_Terminated_LINE_Drive_Enable", 0x0065, (SETTABLE)},

	/* M-PHY RX Capability Attributes */
	{"RX_HSMODE_Capability", 0x0081, (GETTABLE)},
	{"RX_HSGEAR_Capability", 0x0082, (GETTABLE)},
	{"RX_PWMG0_Capability", 0x0083, (GETTABLE)},
	{"RX_PWMGEAR_Capability", 0x0084, (GETTABLE)},
	{"RX_HS_Unterminated_Capability", 0x0085, (GETTABLE)},
	{"RX_LS_Terminated_Capability", 0x0086, (GETTABLE)},
	{"RX_Min_SLEEP_NoConfig_Time_Capability", 0x0087, (GETTABLE)},
	{"RX_Min_STALL_NoConfig_Time_Capability", 0x0088, (GETTABLE)},
	{"RX_Min_SAVE_Config_Time_Capability", 0x0089, (GETTABLE)},
	{"RX_REF_CLOCK_SHARED_Capability", 0x008A, (GETTABLE)},
	{"RX_HS_G1_SYNC_LENGTH_Capability", 0x008B, (GETTABLE)},
	{"RX_HS_G1_PREPARE_LENGTH_Capability", 0x008C, (GETTABLE)},
	{"RX_LS_PREPARE_LENGTH_Capability", 0x008D, (GETTABLE)},
	{"RX_PWM_Burst_Closure_Length_Capability", 0x008E, (GETTABLE)},
	{"RX_Min_ActivateTime_Capability", 0x008F, (GETTABLE)},
	{"RX_PHY_MajorMinor_Release_Capability", 0x0090, (GETTABLE)},
	{"RX_PHY_Editorial_Release_Capability", 0x0091, (GETTABLE)},
	{"RX_Hibern8Time_Capability", 0x0092, (GETTABLE)},
	{"RX_PWM_G6_G7_SYNC_LENGTH_Capability", 0x0093, (GETTABLE)},
	{"RX_HS_G2_SYNC_LENGTH_Capability", 0x0094, (GETTABLE)},
	{"RX_HS_G3_SYNC_LENGTH_Capability", 0x0095, (GETTABLE)},
	{"RX_HS_G2_PREPARE_LENGTH_Capability", 0x0096, (GETTABLE)},
	{"RX_HS_G3_PREPARE_LENGTH_Capability", 0x0097, (GETTABLE)},
	{"RX_Advanced_Granularity_Capability", 0x0098, (GETTABLE)},
	{"RX_Advanced_Hibern8Time_Capability", 0x0099, (GETTABLE)},
	{"RX_Advanced_Min_ActivateTime_Capability", 0x009A, (GETTABLE)},
	{"RX_HS_G4_SYNC_LENGTH_Capability", 0x009B, (GETTABLE)},
	{"RX_HS_G4_PREPARE_LENGTH_Capability", 0x009C, (GETTABLE)},
	{"RX_HS_Equalizer_Setting_Capability", 0x009D, (GETTABLE)},
	{"RX_HS_ADAPT_REFRESH_Capability", 0x009E, (GETTABLE)},
	{"RX_HS_ADAPT_INITIAL_Capability", 0x009F, (GETTABLE)},

	/* M-RX Configuration Attributes */
	{"RX_MODE", 0x00A1, (GETTABLE | SETTABLE)},
	{"RX_HSRATE_Series", 0x00A2, (GETTABLE | SETTABLE)},
	{"RX_HSGEAR", 0x00A3, (GETTABLE | SETTABLE)},
	{"RX_PWMGEAR", 0x00A4, (GETTABLE | SETTABLE)},
	{"RX_LS_Terminated_Enable", 0x00A5, (GETTABLE | SETTABLE)},
	{"RX_HS_Unterminated_Enable", 0x00A6, (GETTABLE | SETTABLE)},
	{"RX_Enter_HIBERN8", 0x00A7, (GETTABLE | SETTABLE)},
	{"RX_BYPASS_8B10B_Enable", 0x00A8, (GETTABLE | SETTABLE)},
	{"RX_Termination_Force_Enable", 0x00A9, (GETTABLE | SETTABLE)},
	{"RX_ADAPT_Control", 0x00AA, (GETTABLE | SETTABLE)},
	{"RX_RECEIVER_POLARITY", 0x00AB, (GETTABLE | SETTABLE)},
	{"RX_HS_ADAPT_LENGTH", 0x00AC, (GETTABLE | SETTABLE)},

	/* M-PHY RX Status Attributes */
	{"RX_FSM_State", 0x00C1, (GETTABLE)},

	/* M-PHY OMC Status Attributes */
	{"OMC_TYPE_Capability", 0x00D1, (GETTABLE)},
	{"MC_HSMODE_Capability", 0x00D2, (GETTABLE)},
	{"MC_HSGEAR_Capability", 0x00D3, (GETTABLE)},
	{"MC_HS_START_TIME_Var_Capability", 0x00D4, (GETTABLE)},
	{"MC_HS_START_TIME_Range_Capability", 0x00D5, (GETTABLE)},
	{"MC_RX_SA_Capability", 0x00D6, (GETTABLE)},
	{"MC_HS_LA_Capability", 0x00D7, (GETTABLE)},
	{"MC_HS_LS_PREPARE_LENGTH", 0x00D8, (GETTABLE)},
	{"MC_PWMG0_Capability", 0x00D9, (GETTABLE)},
	{"MC_PWMGEAR_Capability", 0x00DA, (GETTABLE)},
	{"MC_LS_Terminated_Capability", 0x00DB, (GETTABLE)},
	{"MC_HS_Unterminated_Capability", 0x00DC, (GETTABLE)},
	{"MC_LS_Terminated_LINE_Drive_Capability", 0x00DD, (GETTABLE)},
	{"MC_HS_Unterminated_LINE_Drive_Capabilit", 0x00DE, (GETTABLE)},
	{"MC_MFG_ID_Part1", 0x00DF, (GETTABLE)},
	{"MC_MFG_ID_Part2", 0x00E0, (GETTABLE)},
	{"MC_PHY_MajorMinor_Release_Capability", 0x00E1, (GETTABLE)},
	{"MC_PHY_Editorial_Release_Capability", 0x00E2, (GETTABLE)},
	{"MC_Vendor_Info_Part1", 0x00E3, (GETTABLE)},
	{"MC_Vendor_Info_Part2", 0x00E4, (GETTABLE)},
	{"MC_Vendor_Info_Part3", 0x00E5, (GETTABLE)},
	{"MC_Vendor_Info_Part4", 0x00E6, (GETTABLE)},
};

static struct ufs_unipro_attrs_info uic_attrs_group[MAX_UNIPRO_IDN] = {
	{
		"MIPI M-PHY", mipi_mphy_attrs,
		sizeof(mipi_mphy_attrs) / sizeof(struct ufs_uic_attr_fields)
	},
	{
		"PHY-Adapter", phy_adapter_attrs,
		sizeof(phy_adapter_attrs) / sizeof(struct ufs_uic_attr_fields)
	},
	{
		"DME Attributes for QoS", dme_qos_attrs,
		sizeof(dme_qos_attrs) / sizeof(struct ufs_uic_attr_fields)
	},
};

static struct uic_cmd_result_code resultcode[] = {
	{0, "SUCCESS"},
	{1, "INVALID_MIB_ATTRIBUTE"},
	{2, "INVALID_MIB_ATTRIBUTE_VALUE"},
	{3, "READ_ONLY_MIB_ATTRIBUTE"},
	{4, "WRITE_ONLY_MIB_ATTRIBUTE"},
	{5, "BAD_INDEX"},
	{6, "LOCKED_MIB_ATTRIBUTE"},
	{7, "BAD_TEST_FEATURE_INDEX"},
	{8, "PEER_COMMUNICATION_FAILURE"},
	{9, "BUSY"},
	{10, "DME_FAILURE"},
};

static int ufshcd_dme_get_attr(int fd, __u32 attr_sel, __u8 peer)
{
	struct ufs_bsg_request bsg_req = { 0 };
	struct ufs_bsg_reply bsg_rsp = { 0 };
	struct uic_command *uic_cmd =
		(struct uic_command *)&bsg_req.upiu_req.uc;
	struct uic_command uic_rsq = { 0 };

	int rt = OK;
	__u8 res_code;

	uic_cmd->command = peer ? UIC_CMD_DME_PEER_GET : UIC_CMD_DME_GET;
	uic_cmd->argument1 = attr_sel;
	bsg_req.msgcode = UPIU_TRANSACTION_UIC_CMD;

	rt = send_bsg_scsi_trs(fd, &bsg_req, &bsg_rsp, sizeof(struct ufs_bsg_request),
			       sizeof(struct ufs_bsg_reply), 0, 0, 0);
	if (rt) {
		print_error("%s: bsg request failed", __func__);
		rt = ERROR;
		goto out;
	}

	memcpy(&uic_rsq, &bsg_rsp.upiu_rsp.uc, UIC_CMD_SIZE);
	res_code = uic_rsq.argument2 & MASK_UIC_COMMAND_RESULT;

	if (res_code) {
		__u8 max_code =
		sizeof(resultcode) /
			sizeof(struct uic_cmd_result_code);

		if (res_code < (max_code - 1)) {
			print_error("%s: attr-id 0x%x %s",
				    __func__,
				    UIC_GET_ATTR_ID(attr_sel),
				    resultcode[res_code].def);
		} else {
			print_error("%s: ID 0x%x, unknown error code %d",
				    __func__, UIC_GET_ATTR_ID(attr_sel),
				    res_code);
		}

		rt = ERROR;
	} else {
		rt = uic_rsq.argument3;
	}

out:
	return rt;
}

static int ufshcd_dme_set_attr(int fd, __u32 attr_sel, __u8 attr_set,
			       __u32 mib_val, __u8 peer)
{
	struct ufs_bsg_request bsg_req = { 0 };
	struct ufs_bsg_reply bsg_rsp = { 0 };
	struct uic_command *uic_cmd =
		(struct uic_command *)&bsg_req.upiu_req.uc;
	struct uic_command uic_rsq = { 0 };

	int rt = OK;
	__u8 res_code;

	uic_cmd->command = peer ? UIC_CMD_DME_PEER_SET : UIC_CMD_DME_SET;
	uic_cmd->argument1 = attr_sel;
	uic_cmd->argument2 = UIC_ARG_ATTR_TYPE(attr_set);
	uic_cmd->argument3 = mib_val;

	bsg_req.msgcode = UPIU_TRANSACTION_UIC_CMD;

	rt = send_bsg_scsi_trs(fd, &bsg_req, &bsg_rsp, sizeof(struct ufs_bsg_request),
			       sizeof(struct ufs_bsg_reply), 0, 0, 0);
	if (rt) {
		print_error("%s: bsg request failed", __func__);
		rt = ERROR;
		goto out;
	}

	memcpy(&uic_rsq, &bsg_rsp.upiu_rsp.uc, UIC_CMD_SIZE);
	res_code = uic_rsq.argument2 & MASK_UIC_COMMAND_RESULT;

	if (res_code) {
		__u8 max_code = sizeof(resultcode) /
			sizeof(struct uic_cmd_result_code);

		if (res_code < (max_code - 1)) {
			print_error("%s: ID 0x%x %s",
				    __func__,
				    UIC_GET_ATTR_ID(attr_sel),
				    resultcode[res_code].def);
		} else {
			print_error("%s: ID 0x%x, unkonw error code %d",
				    __func__,
				    UIC_GET_ATTR_ID(attr_sel),
				    res_code);
		}
		rt = ERROR;
	}

out:
	return rt;
}

static int check_attr_id(__u32 idn, __u32 id)
{
	int index;
	int qts = uic_attrs_group[idn].items;
	struct ufs_uic_attr_fields *p = uic_attrs_group[idn].attrs;

	for (index = 0; index < qts; index++) {
		if (p[index].id == id)
			return index;
	}
	return INVALID;
}

static void display(int id, const char *name, int local, int peer)
{
	printf("[0x%04x]%-45s : local = 0x%08x, peer = 0x%08x\n",
	       id, name, local, peer);
}

static int unipro_read(int fd, int idn, int id, __u8 all)
{
	int index, qts;
	int mib_val_local, mib_val_peer;
	int ret = OK;

	qts = uic_attrs_group[idn].items;
	struct ufs_uic_attr_fields *p = uic_attrs_group[idn].attrs;

	if (all) {
		printf("\nUFS Unipro %s layer Attributes:\n",
		       uic_attrs_group[idn].name);

		for (index = 0; index < qts; index++) {
			if (p[index].acc_mode & GETTABLE) {
				mib_val_local =
				ufshcd_dme_get_attr(fd,
						    UIC_ARG_MIB(p[index].id),
						    DME_LOCAL);
				mib_val_peer =
				ufshcd_dme_get_attr(fd,
						    UIC_ARG_MIB(p[index].id),
						    DME_PEER);

				if (mib_val_local != ERROR &&
				    mib_val_peer != ERROR) {
					display(p[index].id, p[index].name,
						mib_val_local, mib_val_peer);
				} else {
					print_error("Read %s ID 0x%x Failed",
						    ((mib_val_local == ERROR) &&
						     (mib_val_peer == ERROR)) ?
						    ("local&peer") :
						    ((mib_val_local == ERROR) ?
						     ("local") : ("peer")),
						    p[index].id);

					ret  = ERROR;
				}
			}
		}
	} else {
		/* read single item */
		index = check_attr_id(idn, id);
		if (index >= 0) {
			mib_val_local =
				ufshcd_dme_get_attr(fd,
						    UIC_ARG_MIB(p[index].id),
						    DME_LOCAL);
			mib_val_peer =
				ufshcd_dme_get_attr(fd,
						    UIC_ARG_MIB(p[index].id),
						    DME_PEER);

			if (mib_val_local != ERROR &&
			    mib_val_peer != ERROR) {
				display(p[index].id, p[index].name,
					mib_val_local, mib_val_peer);
			} else {
				print_error("Read %s ID 0x%x failed",
					    ((mib_val_local == ERROR) &&
					     (mib_val_peer == ERROR)) ?
					    ("local&peer") :
					    ((mib_val_local == ERROR) ?
					     ("local") : ("peer")),
					    p[index].id);
				ret  = ERROR;
			}

		} else {
			print_error("Unsupport ID 0x%02x in %s",
				    id, uic_attrs_group[idn].name);
			ret  = ERROR;
		}
	}

	return ret;
}

static int unipro_write(int fd, int idn, int id, int mib_val,
			int attr_set, int target)
{
	int index;
	int ret = OK;
	struct ufs_uic_attr_fields *p = uic_attrs_group[idn].attrs;

	index = check_attr_id(idn, id);

	if (index >= 0) {
		if (p[index].acc_mode & SETTABLE) {
			ret = ufshcd_dme_set_attr(fd,
						  UIC_ARG_MIB(p[index].id),
						  attr_set, mib_val, target);

			printf("%s set %s 0x%04x:%s to 0x%08x\n",
			       (ret == OK ? "Successfully" : "Failed"),
			       (target == DME_PEER ? "PEER" : "LOCAL"),
			       p[index].id, p[index].name, mib_val);
		} else {
			print_error("un-settable id 0x%02x in %s", id,
				    uic_attrs_group[idn].name);
			ret = ERROR;
		}
	} else {
		print_error("unsupport id 0x%02x in %s", id,
			    uic_attrs_group[idn].name);
		ret = ERROR;
	}

	return ret;
}

int do_uic(struct tool_options *opt)
{
	int fd;
	int rt = OK;
	int oflag = O_RDWR;

	if (opt->opr == READ_ALL || opt->opr == READ)
		oflag = O_RDONLY;

	fd = open(opt->path, oflag);
	if (fd < 0) {
		perror("Device open");
		return ERROR;
	}

	switch (opt->opr) {
	case READ_ALL:
		rt = unipro_read(fd, opt->idn, 0, 1);
		break;
	case READ:
		rt = unipro_read(fd, opt->idn, opt->index, 0);
		break;
	case WRITE:
		rt = unipro_write(fd,
				  opt->idn, opt->index,
				  *(__u32 *)opt->data,
				  ATTR_SET_NOR, opt->target);
		break;
	default:
		rt = INVALID;
		break;
	}
	close(fd);
	return rt;
}

const char *help_str =
	"\nUnipro command usage:\n"
	"  %s uic [-t idn] [-a|-r] [-i ID] [-w data <peer|local>] [-p bsg]\n\n"
	"	-t idn\n"
	"		Supported Unipro layers attributes idn as below:\n"
	"		0:	MIPI M-PHY Attributes\n"
	"		1:	PHY-Adapter Attributes\n"
	"		2:	DME Attributes for QoS\n\n"
	"	-a	Read all gettable attributes of peer & local, please\n"
	"		use -t to specify Unipro attributes idn\n\n"
	"	-r	Read single attribute of peer & local, please use -i\n"
	"		to specify attribute ID, and -t for associated idn\n\n"
	"	-w data <peer|local>\n"
	"		Write settable attribute, followed by data writing,\n"
	"		Please use -i to specify which ID to write, --peer\n"
	"		and --local to specify accessed target\n\n"
	"		  --peer  : access to a peer device (UFS device)\n"
	"		  --local : access to a local device (UFS host)\n\n"
	"	-i ID\n"
	"		Set attribute ID to read/write\n"
	"	-p bsg\n"
	"		Path to ufs-bsg device\n\n"
	"  Note :\n"
	"	As for the format of the data inputted, hex number should be\n"
	"	prefixed by 0x/0X\n"
	"  Eg :\n"
	"	1. Set local PA_TxTrailingClocks:\n"
	"	%s uic -t 1 -w 0x44 -i 0x1564 --local -p /dev/ufs-bsg\n"
	"	2. Read peer and local PA_TxTrailingClocks:\n"
	"	%s uic -t 1 -r -i 0x1564 -p /dev/ufs-bsg\n";
void unipro_help(char *tool_name)
{
	printf(help_str, tool_name, tool_name, tool_name);
}
