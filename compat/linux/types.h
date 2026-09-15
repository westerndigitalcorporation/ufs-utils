/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Copyright (C) 2026 Samsung Electronics Co., Ltd. */
/*
 * Stand-in for the Linux kernel header of the same name. ufs-utils only
 * needs the fixed width typedefs from it.
 */

#ifndef COMPAT_LINUX_TYPES_H_
#define COMPAT_LINUX_TYPES_H_

#include <stdint.h>

typedef uint8_t  __u8;
typedef uint16_t __u16;
typedef uint32_t __u32;
typedef unsigned long long __u64;
typedef int8_t   __s8;
typedef int16_t  __s16;
typedef int32_t  __s32;
typedef long long __s64;

/*
 * The byte order in these names is documentation only. ufs-utils converts
 * with the htobe and betoh macros at every use, so a plain typedef is
 * enough.
 */
typedef uint16_t __le16;
typedef uint32_t __le32;
typedef unsigned long long __le64;
typedef uint16_t __be16;
typedef uint32_t __be32;
typedef unsigned long long __be64;

#endif /* COMPAT_LINUX_TYPES_H_ */
