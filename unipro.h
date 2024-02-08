/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2017 Micron Technology Inc.
 *
 * Author:
 *	Bean Huo <beanhuo@micron.com>
 */
#ifndef UNIPRO_H_
#define UNIPRO_H_

#define UIC_ARG_MIB_SEL(attr, sel)  ((((attr) & 0xFFFF) << 16) |\
		((sel) & 0xFFFF))
#define UIC_ARG_MIB(attr)   UIC_ARG_MIB_SEL(attr, 0)
#define UIC_ARG_ATTR_TYPE(t)    (((t) & 0xFF) << 16)
#define UIC_GET_ATTR_ID(v)  (((v) >> 16) & 0xFFFF)

/* UIC command interfaces for DME primitives */
#define DME_LOCAL       0
#define DME_PEER        1
#define ATTR_SET_NOR    0       /* NORMAL */
#define ATTR_SET_ST     1       /* STATIC */
#define MASK_UIC_COMMAND_RESULT 0xFF

/* uic commands are 4DW long, per UFSHCI V2.1 paragraph 5.6.1 */
#define UIC_CMD_SIZE (sizeof(__u32) * 4)

/**
 * struct uic_command - UIC command structure
 * @command: UIC command
 * @argument1: UIC command argument 1
 * @argument2: UIC command argument 2
 * @argument3: UIC command argument 3
 */
struct uic_command {
	__u32 command;
	__u32 argument1;
	__u32 argument2;
	__u32 argument3;
};

enum unipro_acc_mode {
	GETTABLE = (1 << 0),
	SETTABLE = (1 << 1),
	STATIC = (1 << 2),
	DYNAMIC = (1 << 3)
};

struct ufs_uic_attr_fields {
	const char *name;
	__u32 id;
	enum unipro_acc_mode acc_mode;
};

struct ufs_unipro_attrs_info {
	const char *name;
	struct ufs_uic_attr_fields *attrs;
	__u32 items;
};

struct uic_cmd_result_code {
	__u8 value;
	const char *def;
};

/* Unipro attribute idn */
enum unipro_attr_idn {
	MPHY = 0x00,
	PHY_ADAPTER = 0x01,
	DME_QOS = 0X02,
	MAX_UNIPRO_IDN,
};

/* UIC Commands */
enum uic_cmd_dme {
	UIC_CMD_DME_GET = 0x01,
	UIC_CMD_DME_SET = 0x02,
	UIC_CMD_DME_PEER_GET = 0x03,
	UIC_CMD_DME_PEER_SET = 0x04,
	UIC_CMD_DME_POWERON = 0x10,
	UIC_CMD_DME_POWEROFF = 0x11,
	UIC_CMD_DME_ENABLE = 0x12,
	UIC_CMD_DME_RESET = 0x14,
	UIC_CMD_DME_END_PT_RST = 0x15,
	UIC_CMD_DME_LINK_STARTUP = 0x16,
	UIC_CMD_DME_HIBER_ENTER = 0x17,
	UIC_CMD_DME_HIBER_EXIT = 0x18,
	UIC_CMD_DME_TEST_MODE = 0x1A,
};

int do_uic(struct tool_options *opt);
void unipro_help(char *tool_name);

#endif	/* END UNIPRO_H_ */
