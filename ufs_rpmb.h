/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Copyright (C) 2019 Western Digital Corporation or its affiliates */

#include <stdint.h>
#include <fcntl.h>
#include <unistd.h>
#include "options.h"

#ifndef UFS_RPMB_H_
#define UFS_RPMB_H_

#define RPMB_KEY_SIZE 32
#define RPMB_MAC_SIZE 32
#define RPMB_NONCE_SIZE 16
#define RPMB_DATA_SIZE 256

#define DEFAULT_RPMB_NUM_BLOCKS 64

/* RPMB Data Area: 128 Kbytes minimum, 16 Mbytes maximum.
 * For the normal RPMB mode, since the data packed in RPMB message, the size of each frame is 256
 * bytes. so its MAX_ADDRESS == 0xFFFF.
 *
 * For the ADvanced RPMB mode, the Data Transfer Length unit is 4KB, so its MAX_ADDRESS ==
 * 16MB / 4KB = 0xFFF. Note: the address starts at 0x00
 */
#define MAX_ADDRESS 0xFFFF
#define ARPMB_MAX_ADDRESS 0xFFF

#define CUC(x) ((const unsigned char *)(x))

enum rpmb_cmd_type {
	AUTHENTICATION_KEY = 0,
	READ_WRITE_COUNTER,
	READ_RPMB,
	WRITE_RPMB,
	WRITE_SEC_RPMB_CONF_BLOCK,
	READ_SEC_RPMB_CONF_BLOCK,
	RPMB_CMD_MAX
};

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

void rpmb_help(char *tool_name);
int do_rpmb(struct tool_options *opt);
void arpmb_help(char *tool_name);
int do_arpmb(struct tool_options *opt);

static inline void  print_operation_error(__u16 result)
{
	if (result <= 0xA)
		printf("\n %s\n", rpmb_res_txt[result]);
	else
		printf("\n Unsupported RPMB Operation Error %x\n", result);
}

static inline unsigned char *get_auth_key(char *key_path, unsigned char * key_buff)
{
        unsigned char *pkey = NULL;
        int key_fd = INVALID;
        ssize_t read_size;

        if (key_path == NULL || key_buff == NULL)
                return NULL;

        key_fd = open(key_path, O_RDONLY);
        if (key_fd < 0) {
                perror("Key file open");
        } else {
                read_size = read(key_fd, key_buff, RPMB_KEY_SIZE);
                if (read_size < RPMB_KEY_SIZE) {
                        print_error("Key must be %d bytes length,was read %d",
                                    RPMB_KEY_SIZE, read_size);
                } else
                        pkey = key_buff;
        }

        if (key_fd != INVALID)
                close(key_fd);
        return pkey;
}
#endif /* UFS_RPMB_H_ */
