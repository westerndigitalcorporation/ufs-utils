// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2019 Western Digital Corporation or its affiliates */

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>

#include "ufs.h"
#include "ufs_hmr.h"
#include "ufs_cmds.h"

/*
 * HMR Quirks: 1 - enable, 0 - disable
 */

/*
 * Big-little-endian byte order: some params
 * may occur in order other than expected.
 * Change byte order for the following params.
 */
#define HMR_QUIRK_REFRESH_TOTCOUNT_BYTE_ORDER	1
#define HMR_QUIRK_REFRESH_PROGRESS_BYTE_ORDER	1

/*
 * There is the maximum number of HMR operations in the life
 * of the device. Having reached this number, the device will
 * return "General Failure" and set the bRefreshStatus attribute
 * to 0x05.
 */
#define HMR_REFRESH_MAX_TOTCOUNT	200

/*
 * Output progress every N iterations.
 */
#define HMR_PROGRESS_OUTPUT_ITER	1
#if HMR_PROGRESS_OUTPUT_ITER <= 0
#	error keep HMR_PROGRESS_OUTPUT_ITER > 0
#endif

/*
 * The HMR mode type description string size we
 * support to output. Can be enlarged if required.
 */
#define HMR_MODE_TYPE_MAX_SIZE	40

enum hmr_err_codes {
	EHMR_OK					= 0,	/* success */
	EHMR_REFRESH_PROGRESS	= 100,	/* wrong refresh progress */
	EHMR_REFRESH_STATUS,			/* wrong refresh status */
	EHMR_REFRESH_TOTCOUNT,			/* wrong refresh total count */
	EHMR_FREEMEM,					/* memory wasn't freed */
	EHMR_NOMEM,						/* not enough memory */
	EHMR_INVAL,						/* invalid argument */
	EHMR_NORETRY,					/* cannot be retried */
	EHMR_REFRESH_METHOD,			/* wrong refrresh method  */
	EHMR_REFRESH_UNIT,				/* wrong refrresh unit */
};

enum hmr_refresh_status {
	HMR_ST_IDLE = 0,
	HMR_ST_IN_PROGRESS,
	HMR_ST_ABORTED,
	HMR_ST_COMPLETED,
	HMR_ST_BUSY,
	HMR_ST_GENERAL,
};

enum hmr_stage_skip {
	HMR_SKIP_STATUS_CHECK	= 1 << 0,
	HMR_SKIP_METHOD_SET		= 1 << 1,
	HMR_SKIP_UNIT_SET		= 1 << 2,
};

#pragma pack(push, 1)
struct descriptor_health_layout {
	__u8  length;
	__u8  type;
	__u8  pre_eol_info;
	__u8  dev_life_time_est_a;
	__u8  dev_life_time_est_b;
	__u8  vendor_prop_info[0x20];
	__u32 refresh_total_count;
	__u32 refresh_progress;
};
#pragma pack(pop)

struct descriptor {
	const char *name;
	size_t size;
	void *layout;
};

extern int do_query_rq(int fd,
	struct ufs_bsg_request *bsg_req,	/* request  struct of the sg_io_v4 */
	struct ufs_bsg_reply *bsg_rsp,		/* response struct of the sg_io_v4 */
	__u8 query_req_func,				/* read / write */
	__u8 opcode,						/* opcode r/w of desc/attr/fl etc.*/
	__u8 idn,							/* (-t) util option */
	__u8 index,							/* (-i) util option */
	__u8 sel,							/* (-s) util option */
	__u16 req_buf_len,					/* request buffer size */
	__u16 res_buf_len,					/* response buffer size */
	__u8 *data_buf);					/* buffer with/for data */

extern struct desc_field_offset device_health_desc_conf_field_name[];
extern struct attr_fields ufs_attrs[];
extern struct flag_fields ufs_flags[];

static struct descriptor_health_layout desc_health_layout;

static struct descriptor desc_health = {
	"Health",
	sizeof desc_health_layout,
	&desc_health_layout
};

static inline void hmr_delay_retry(int sec)
{
	if (sec > 0)
		sleep(sec);
}

static inline void hmr_output_message(const char *msg)
{
	/*
	 * |---------------------------------------------------------|
	 * | Message format template:                                |
	 * |---------------------------------------------------------|
	 * |<<-6->|   |<<-29->                                       |
	 * |HMR:  |   |variable string                               |
	 * |                                                         |
	 * |---------------------------------------------------------|
	 * |HMR:  |   |waiting idle status                           |
	 * |---------------------------------------------------------|
	 */
	printf("%-6s   %-29s\r",  "HMR:", msg);
	fflush(stdout);
}

static inline void hmr_output_progress(__u32 progress,
	__u64 iter, int sec, const char *msg)
{
	/*
	 * |---------------------------------------------------------|
	 * | Progress format template:                               |
	 * |---------------------------------------------------------|
	 * |<<-6->| |   <-9->>|  |<<-35->                            |
	 * |HMR:  | |  hex dig|  |variable string                    |
	 * |                                                         |
	 * |---------------------------------------------------------|
	 * | The case of up to 100% progress:                        |
	 * |---------------------------------------------------------|
	 * |<<-6->| |   <-9->>|  |<<-35->                            |
	 * |HMR:  | |     f20a|  |                                   |
	 * |      | |         |  |                                   |
	 * |---------------------------------------------------------|
	 * | The case of 100% progress:                              |
	 * |---------------------------------------------------------|
	 * |<<-6->| |  <-8->>|   |<<-20->                            |
	 * |HMR:  | |     100|%  |                                   |
	 * |---------------------------------------------------------|
	 */

	/*
	 * Completed - print 100%,
	 * otherwise print hex progress indicator every N iterations.
	 */
	if (!progress)
		printf("%-6s %8d%%  %-20s\r", "HMR:", 100, msg);
	else if (0 == (iter % HMR_PROGRESS_OUTPUT_ITER))
		printf("%-6s %9x  %-20s\r",  "HMR:", progress, msg);

	fflush(stdout);
	if (sec > 0)
		sleep(sec);
}

static inline void hmr_output_header(const char *unit_str, int method)
{
	int count;
	const char *method_str;
	char mode_str[HMR_MODE_TYPE_MAX_SIZE];

	method_str = method == HMR_METHOD_FORCE ? "force" : "selective";

	count = snprintf(mode_str, sizeof mode_str, "method:%s, unit:%s",
		method_str, unit_str);

	if (count >= HMR_MODE_TYPE_MAX_SIZE)
		; /* the output was truncated, enlarge HMR_MODE_TYPE_MAX_SIZE */

	/*
	 * |---------------------------------------------------------|
	 * | Header format template:                                 |
	 * |---------------------------------------------------------|
	 * |<<-6->| |   <-9->>|  |<<-35->                            |
	 * |HMR:  | |   status|  |mode type                          |
	 * |                                                         |
	 * |---------------------------------------------------------|
	 * | Examples:                                               |
	 * |---------------------------------------------------------|
	 * |HMR:  | |  started|  |method:selective, unit:minimum     |
	 * |      | |         |  |                                   |
	 * |---------------------------------------------------------|
	 * |HMR:  | |  started|  |method:force, unit:full            |
	 * |      | |         |  |                                   |
	 * |---------------------------------------------------------|
	 */
	printf("%-6s %9s  %-30s\n", "HMR:", "started", mode_str);
	fflush(stdout);
}

static inline void hmr_output_footer(int rc)
{
	/*
	 * |---------------------------------------------------------|
	 * | Footer format template:                                 |
	 * |---------------------------------------------------------|
	 * |<<-6->| |   <-9->>|  |<<-35->                            |
	 * |HMR:  | |   status|  |error msg / code                   |
	 * |                                                         |
	 * |---------------------------------------------------------|
	 * | Examples:                                               |
	 * |---------------------------------------------------------|
	 * |HMR:  | |completed|  | OK                                |
	 * |      | |         |  |                                   |
	 * |---------------------------------------------------------|
	 * |HMR:  | |  stopped|  |-115                               |
	 * |      | |         |  |                                   |
	 * |---------------------------------------------------------|
	 */

	/*
	 * Leading LF is due to CR-ending on progress print out.
	 * In case of error LF was already sent with the error msg.
	 */
	if (0 == rc)
		printf("\n%-6s %9s  %-30s\n", "HMR:", "completed", "OK");
	else
		printf("%-6s %9s  %-30d\n", "HMR:", "stopped", rc);

	fflush(stdout);
}

static inline void hmr_query_error(int rc,
	const char *job_type,		/* write/read/set/clear/etc. */
	const char *subject,		/* desc/attr/flag/etc. */
	int opcode,					/* opcode r/w of desc/attr/fl etc. */
	const char *field_name,		/* name of the operated field */
	int field_idn)				/* index of the field */
{
	print_error("hmr: query command: %s %s failed: "
		"opcode 0x%x, field-name %s, field-idn 0x%x, rc %d.\n",
		job_type, subject, opcode, field_name, field_idn);
}

static inline int hmr_attr_sanity(enum attr_idn idn)
{
	if (idn < 0 || idn >= QUERY_ATTR_IDN_MAX)
		return -EHMR_INVAL;

	return EHMR_OK;
}

static inline int hmr_flag_sanity(enum flag_idn idn)
{
	if (idn < 0 || idn >= QUERY_FLAG_IDN_MAX)
		return -EHMR_INVAL;

	return EHMR_OK;
}

static inline int hmr_desc_sanity(enum desc_idn idn)
{
	if (idn < 0 || idn >= QUERY_DESC_IDN_MAX)
		return -EHMR_INVAL;

	return EHMR_OK;
}

static int hmr_dev_open(const char* path, int *fd)
{
	int rc = EHMR_OK;

	errno = 0;

	*fd = open(path, O_RDWR);
	if (*fd < 0) {
		rc = errno; /* save errno: errno can be changed by the print */
		print_error("hmr: %s: '%s'", strerror(rc), path);
	}

	return rc == EHMR_OK ? rc : -rc;
}

static int hmr_attr_read(__u32 *result,
	int fd,
	struct ufs_bsg_request *bsg_req,
	struct ufs_bsg_reply   *bsg_rsp,
	enum attr_idn idn)
{
	int rc;
	struct attr_fields *field;

	if (hmr_attr_sanity(idn) != EHMR_OK || !result)
		return -EHMR_INVAL;

	field = &ufs_attrs[idn];

	/* Query to read attribute */
	rc = do_query_rq(fd,
		bsg_req,
		bsg_rsp,
		UPIU_QUERY_FUNC_STANDARD_READ_REQUEST,
		UPIU_QUERY_OPCODE_READ_ATTR,
		idn,
		0,
		0,
		0,
		0,
		0);

	if (rc) {
		hmr_query_error(rc, "read", "attr", UPIU_QUERY_OPCODE_READ_ATTR,
			field->name, idn);
		goto out;
	}

	*result = be32toh(bsg_rsp->upiu_rsp.qr.value);

out:
	return rc;
}

static int hmr_attr_write(__u32 value,
	int fd,
	struct ufs_bsg_request *bsg_req,
	struct ufs_bsg_reply   *bsg_rsp,
	enum attr_idn idn)
{
	int rc;
	struct attr_fields *field;

	if (hmr_attr_sanity(idn) != EHMR_OK)
		return -EHMR_INVAL;

	field = &ufs_attrs[idn];

	bsg_req->upiu_req.qr.value = htobe32(value);

	/* Query to write attribute */
	rc = do_query_rq(fd,
		bsg_req,
		bsg_rsp,
		UPIU_QUERY_FUNC_STANDARD_WRITE_REQUEST,
		UPIU_QUERY_OPCODE_WRITE_ATTR,
		idn,
		0,
		0,
		0,
		0,
		0);

	if (rc)
		hmr_query_error(rc, "write", "attr", UPIU_QUERY_OPCODE_WRITE_ATTR,
			field->name, idn);

	return rc;
}

static int hmr_flag_modify(int fd,
	struct ufs_bsg_request *bsg_req,
	struct ufs_bsg_reply   *bsg_rsp,
	enum query_opcode opcode,
	enum flag_idn idn)
{
	int rc;
	struct flag_fields *field;

	if (opcode != UPIU_QUERY_OPCODE_SET_FLAG &&
		opcode != UPIU_QUERY_OPCODE_CLEAR_FLAG &&
		opcode != UPIU_QUERY_OPCODE_TOGGLE_FLAG)
		return -EHMR_INVAL;

	if (hmr_flag_sanity(idn) != EHMR_OK)
		return -EHMR_INVAL;

	field = &ufs_flags[idn];

	/* Query to set/clear/toggle flag */
	rc = do_query_rq(fd,
		bsg_req,
		bsg_rsp,
		UPIU_QUERY_FUNC_STANDARD_WRITE_REQUEST,
		opcode,
		idn,
		0,
		0,
		0,
		0,
		0);

	if (rc)
		hmr_query_error(rc, "modify", "flag", opcode, field->name, idn);

	return rc;
}

static int hmr_desc_read(struct descriptor *result,
	int fd,
	struct ufs_bsg_request *bsg_req,
	struct ufs_bsg_reply   *bsg_rsp,
	enum desc_idn idn)
{
	int rc;

	if (hmr_desc_sanity(idn) != EHMR_OK ||
		!result ||
		!result->layout ||
		result->size <= 0)
		return -EHMR_INVAL;

	/* Query to read descriptor */
	rc = do_query_rq(fd,
		bsg_req,
		bsg_rsp,
		UPIU_QUERY_FUNC_STANDARD_READ_REQUEST,
		UPIU_QUERY_OPCODE_READ_DESC,
		idn,
		0,
		0,
		0,
		result->size,
		result->layout);

	if (rc)
		hmr_query_error(rc, "read", "desc", UPIU_QUERY_OPCODE_READ_DESC,
			result->name, idn);

	return rc;
}

static int hmr_progress_read(__u32 *result,
	int fd,
	struct ufs_bsg_request *bsg_req,
	struct ufs_bsg_reply   *bsg_rsp)
{
	int rc;
	struct descriptor *desc;
	struct descriptor_health_layout *layout;

	desc = &desc_health;

	/* Read descriptor Health */
	rc = hmr_desc_read(desc,
		fd,
		bsg_req,
		bsg_rsp,
		QUERY_DESC_IDN_HEALTH);

	if (rc)
		goto out;

	layout = desc->layout;

	if (!HMR_QUIRK_REFRESH_PROGRESS_BYTE_ORDER)
		*result = be32toh(layout->refresh_progress);
	else
		*result = layout->refresh_progress;

	return rc;

out:
	print_error("hmr: read progress: failed.");
	return rc;
}

static int inline hmr_method_set(int fd, int method)
{
	int rc;
	struct ufs_bsg_request bsg_req = {0};
	struct ufs_bsg_reply   bsg_rsp = {0};

	/* Set attribute bRefreshMethod - force or selective */
	rc = hmr_attr_write(method,
		fd, &bsg_req, &bsg_rsp, QUERY_ATTR_IDN_REFRESH_METHOD);

	return rc;
}

static inline int hmr_unit_set(int fd, int unit)
{
	int rc;
	struct ufs_bsg_request bsg_req = {0};
	struct ufs_bsg_reply   bsg_rsp = {0};

	/* Set attribute bRefreshUnit - minimum or full */
	rc = hmr_attr_write(unit,
		fd, &bsg_req, &bsg_rsp, QUERY_ATTR_IDN_REFRESH_UNIT);

	return rc;
}

static inline int hmr_precondition_verify_status(int fd,
	struct ufs_bsg_request *bsg_req,
	struct ufs_bsg_reply *bsg_rsp)
{
	int rc;
	int cur = 0;
	int count = 10;
	__u32 result;

retry:
	/* Read refresh status */
	rc = hmr_attr_read(&result,
		fd,
		bsg_req,
		bsg_rsp,
		QUERY_ATTR_IDN_REFRESH_STATUS);
	if (rc)
		goto out;

	if (result != HMR_ST_IDLE) {
		/* One time only */
		if (0 == cur)
			hmr_output_message("waiting idle status");

		/* Retry */
		if (++cur <= count) {
			hmr_delay_retry(1);
			goto retry;
		}

		/* Error */
		print_error("hmr: precondition: "
			"refresh status != 0x%x (0x%x)", HMR_ST_IDLE, result);
		rc = -EHMR_REFRESH_STATUS;
	}

out:
	return rc;
}

static inline int hmr_precondition_validate_totcount(__u32 *result,
	struct descriptor_health_layout *layout)
{
	int rc = EHMR_OK;
	__u32 refresh_totcount;

	if (!result || !layout)
		return -EHMR_INVAL;

	if (!HMR_QUIRK_REFRESH_TOTCOUNT_BYTE_ORDER)
		refresh_totcount = be32toh(layout->refresh_total_count);
	else
		refresh_totcount = layout->refresh_total_count;

	if (refresh_totcount >= HMR_REFRESH_MAX_TOTCOUNT) {
		print_error("hmr: precondition: "
			"refresh total count  >= max (0x%x >= 0x%x).",
			refresh_totcount, HMR_REFRESH_MAX_TOTCOUNT);
		rc = -EHMR_REFRESH_TOTCOUNT;
		goto out;
	}

	*result = refresh_totcount;

out:
	return rc;
}

static inline void hmr_output_wrong_run(int method, int unit)
{
	print_error("hmr: precondition: device's hmr-progress is not empty. "
		"Run is possible only with the method: %d, unit: %d",
		method, unit);
}

static int hmr_precondition_verify_run(int fd,
	int req_method, int req_unit, enum hmr_stage_skip *stage_passer)
{
	int rc;
	__u32 dev_method;
	__u32 dev_unit;
	__u32 dev_progress;

	struct ufs_bsg_request bsg_req = {0};
	struct ufs_bsg_reply   bsg_rsp = {0};

	if (!stage_passer)
		return -EHMR_INVAL;

	/*
	 * This code is intended to solve the case when the
	 * utility was run while HMR progress is not empty.
	 * It can happen, for example, when running the utility
	 * in one mode, then exit and run it again in some
	 * other mode, while the underline device's HMR status
	 * is still in progress.
	 *
	 * Let's make the policy simple:
	 * 1. Refresh progress is 0 -> OK.
	 * 2. Requested method equal device method
	 *			and
	 *    Requested unit equal device unit
	 *    1) Unit is minimum -> OK.
	 *	  2) Unit is full    -> OK, but have to skip the check for
	 *							refresh status to be "idle", since
	 *						    in this mode it is "in-progress"
	 *							until the HMR is completed.
	 * 3. Any other case is considered as violation.
	 */

	/* Read progress */
	rc = hmr_progress_read(&dev_progress, fd, &bsg_req, &bsg_rsp);
	if (rc)
		goto out;

	/* Clean run, may proceed with HMR */
	if (0 == dev_progress)
		goto out;

	/* Read method */
	rc = hmr_attr_read(&dev_method,
		fd,
		&bsg_req,
		&bsg_rsp,
		QUERY_ATTR_IDN_REFRESH_METHOD);
	if (rc)
		goto out;

	/* Read unit */
	rc = hmr_attr_read(&dev_unit,
		fd,
		&bsg_req,
		&bsg_rsp,
		QUERY_ATTR_IDN_REFRESH_UNIT);
	if (rc)
		goto out;

	/* Method is different, set error */
	if (req_method != dev_method) {
		hmr_output_wrong_run(dev_method, dev_unit);
		rc = -EHMR_REFRESH_UNIT;
		goto out;
	}

	/* Unit is different, set error */
	if (req_unit != dev_unit) {
		hmr_output_wrong_run(dev_method, dev_unit);
		rc = -EHMR_REFRESH_METHOD;
		goto out;
	}

	/*
	 * The progress is not empty, and method/unit are the same.
	 *
	 * 1. Unit type is full? - skip the refresh status check,
	 *    since it will never be completed/idle in this mode until ends.
	 * 2. Skip set method and unit, no need - the values are already set.
	 */
	if (dev_unit == HMR_UNIT_FULL)
		*stage_passer |= HMR_SKIP_STATUS_CHECK;

	 *stage_passer |= (HMR_SKIP_METHOD_SET | HMR_SKIP_UNIT_SET);

out:
	return rc;
}

static int hmr_precondition_verify(int fd,
	struct tool_options *opt, __u32 *totcount,
	enum hmr_stage_skip *stage_passer)
{
	int rc;
	struct descriptor *desc;
	struct ufs_bsg_request bsg_req = {0};
	struct ufs_bsg_reply   bsg_rsp = {0};

	if (!opt || !totcount || !stage_passer)
		return -EHMR_INVAL;

	/*
	 * 1. Verify the run perspective.
	 *
	 * In case of non-empty progress, make a decision
	 * if the run still can be proceeded.
	 */
	rc = hmr_precondition_verify_run(fd,
		opt->hmr_method, opt->hmr_unit, stage_passer);
	if (rc)
		goto err;

	/*
	 * 2. Verify refresh total count.
	 *
	 * Note: the Health descriptor was already read in
	 * hmr_precondition_verify_run(), so updated
	 * refresh total count is already available.
	 */
	desc = &desc_health;
	rc = hmr_precondition_validate_totcount(totcount, desc->layout);
	if (rc)
		goto err;

	/* Skip the refresh status check */
	if (*stage_passer & HMR_SKIP_STATUS_CHECK)
		goto success;

	/*
	 * 3. Verify refresh status.
	 *
	 * Read refresh status.
	 * In case the status is not Idle - retry.
	 *
	 * We are expecting here to get the Idle status (0x00),
	 * but in some cases the status may be different:
	 * aborted (0x02), completed (0x03), etc.
	 *
	 * Usually, the statuses of this kind are saved until
	 * the first reading of the attribute is occured, then
	 * the value o the attribute should be change to Idle (0x00),
	 * but let's be generous and give it a sufficient number of
	 * retries.
	 */
	 rc = hmr_precondition_verify_status(fd, &bsg_req, &bsg_rsp);
	 if (rc)
		goto err;

success:
	return rc;

err:
	print_error("hmr: precondition failed.");
	return rc;
}

static inline int hmr_postcondition_verify_progress(int fd,
	struct ufs_bsg_request *bsg_req,
	struct ufs_bsg_reply *bsg_rsp)
{
	int rc;
	__u32 result;

	/* Read Health descriptor, and get refresh progress field */
	rc = hmr_progress_read(&result, fd, bsg_req, bsg_rsp);
	if (rc)
		goto out;

	/* Progress should be 0 on HMR completion */
	if (result != 0) {
		print_error("hmr: postcondition: "
			"refresh progress != 0x0 (0x%x).", result);
		rc = -EHMR_REFRESH_PROGRESS;
		goto out;
	}

out:
	return rc;
}

static inline int hmr_postcondition_verify_status(int fd,
	struct ufs_bsg_request *bsg_req,
	struct ufs_bsg_reply *bsg_rsp)
{
	int rc;
	__u32 result;

	/* Read refresh status */
	rc = hmr_attr_read(&result,
		fd,
		bsg_req,
		bsg_rsp,
		QUERY_ATTR_IDN_REFRESH_STATUS);

	if (rc)
		goto out;

	/* The accepted statuses are Completed and Idle */
	if (result != HMR_ST_COMPLETED && result != HMR_ST_IDLE) {
		print_error("hmr: postcondition: "
			"refresh status != (0x%x or 0x%x) (0x%x)",
			HMR_ST_COMPLETED, HMR_ST_IDLE, result);
		rc = -EHMR_REFRESH_STATUS;
		goto out;
	}

out:
	return rc;
}

static inline int hmr_postcondition_verify_totcount(__u32 prev_totcount,
		struct descriptor_health_layout *layout)
{
	int rc = EHMR_OK;
	__u32 result;

	if (!layout)
		return -EHMR_INVAL;

	if (!HMR_QUIRK_REFRESH_TOTCOUNT_BYTE_ORDER)
		result = be32toh(layout->refresh_total_count);
	else
		result = layout->refresh_total_count;

	if (result <= prev_totcount) {
		print_error("hmr: postcondition: "
			"refresh total count 0x%x <= 0x%x.",
			prev_totcount, result);
		rc = -EHMR_REFRESH_TOTCOUNT;
	}

	return rc;
}

static int hmr_postcondition_verify(int fd, __u32 totcount)
{
	int rc;
	struct ufs_bsg_request bsg_req = {0};
	struct ufs_bsg_reply   bsg_rsp = {0};
	struct descriptor *desc;

	desc = &desc_health;

	/*
	 * 1. Verify refresh progress.
	 *
	 * Progress equal to 0 indicates refresh was completed.
	 */
	rc = hmr_postcondition_verify_progress(fd, &bsg_req, &bsg_rsp);
	if (rc)
		goto err;

	/*
	 * 2. Check refresh status.
	 *
	 * The expected value is Completed (0x03) in first read,
	 * and Idle (0x00) in any following read (assuming no new
	 * HMR process begins).
	 * Perhaps, depending on the type of test, the first reading
	 * has already taken place. Therefore, we may consider both
	 * values to be valid.
	 */
	rc = hmr_postcondition_verify_status(fd, &bsg_req, &bsg_rsp);
	if (rc)
		goto err;

	/*
	 * 3. Verify refresh total count.
	 *
	 * Refresh total count expected to be increased
	 * upon completion.
	 *
	 * The health descriptor was already read in step 1
	 * doing hmr_progress_read(). Just use its layout.
	 */
	rc = hmr_postcondition_verify_totcount(totcount, desc->layout);
	if (rc)
		goto err;

	/* Success */
	return rc;

err:
	print_error("hmr: postcondition failed.");
	return rc;
}

static inline int hmr_refresh_initiate_retry(int fd,
	struct ufs_bsg_request *bsg_req,
	struct ufs_bsg_reply *bsg_rsp,
	int cur,
	int count)
{
	int rc;
	__u32 result;

	if (cur > count)
		return -EHMR_NORETRY;

	/*
	 * Read refresh status.
	 * Then retry only in case the status is Busy.
	 */
	rc = hmr_attr_read(&result,
		fd,
		bsg_req,
		bsg_rsp,
		QUERY_ATTR_IDN_REFRESH_STATUS);

	if (rc)
		goto out;

	/* Other than Busy - canot be retried */
	if (result != HMR_ST_BUSY) {
		rc =  -EHMR_NORETRY;
		goto out;
	}

out:
	/* 0 - can be retried, otherwise cannot */
	return rc;
}

static int hmr_refresh_initiate(int fd,
	struct ufs_bsg_request *bsg_req,
	struct ufs_bsg_reply *bsg_rsp)
{
	int rc;
	int err;
	int cur = 0;
	int count = 10;

	/*
	 * Initiate refresh.
	 * For that, set flag fRefreshEnable to 1.
	 * In case device command queues are not empty,
	 * this query request may fail. In such a case
	 * the bRefreshStatus attribite shell be set to
	 * 0x04 - HMR_ST_BUSY. This case is handled by
	 * hmr_refresh_initiate_retry().
	 */
retry:
	rc = hmr_flag_modify(fd, bsg_req, bsg_rsp,
		UPIU_QUERY_OPCODE_SET_FLAG,
		QUERY_FLAG_IDN_REFRESH_ENABLE);

	/* Success */
	if (!rc)
		goto out;

	/* Check query can be retried */
	err = hmr_refresh_initiate_retry(fd, bsg_req, bsg_rsp, ++cur, count);
	if (!err) {
		hmr_delay_retry(1);
		goto retry;
	}

	print_error("hmr: initiate unit refresh: setting flag "
		"fRefreshEnable failed after %d retries (%d).", count, rc);

out:
	return rc;
}

static int hmr_unit_verify_completed(int fd,
	struct ufs_bsg_request *bsg_req,
	struct ufs_bsg_reply *bsg_rsp)
{
	__u32 result;
	int rc;
	int cur = 0;
	int count = 10;

	/*
	 * Read refresh status.
	 *
	 * The expected status is Completed, which changes to Idle
	 * after it was read once. Thus, if a given attribute reads
	 * some other process, then we are in a race state and there
	 * is a possibility that the attribute value will be reset
	 * to Idle by another process. Thus, we will consider both
	 * statuses - Completed and Idle as valid at this stage.
	 */
retry:
	rc = hmr_attr_read(&result,
		fd,
		bsg_req,
		bsg_rsp,
		QUERY_ATTR_IDN_REFRESH_STATUS);

	/* Error or (Completed / Idle) */
	if (rc ||
		result == HMR_ST_COMPLETED ||
		result == HMR_ST_IDLE)
		goto out;

	/* Retry */
	if (++cur <= count) {
		hmr_delay_retry(1);
		goto retry;
	}

	/*
	 * Cannot be completed, result holds
	 * other than HMR_ST_COMPLETED or HMR_ST_IDLE status.
	 */
	rc = -EHMR_REFRESH_STATUS;
	print_error("hmr: verify unit completed: getting status "
		"completed failed after %d retries (%d).", count, result);

out:
	return rc;
}

static int hmr_full_start(int fd, int method)
{
	int rc;
	__u32 result;
	__u64 iter = 0;

	struct ufs_bsg_request bsg_req = {0};
	struct ufs_bsg_reply   bsg_rsp = {0};

	hmr_output_header("full", method);

	/* Start full refresh */
	rc = hmr_refresh_initiate(fd, &bsg_req, &bsg_rsp);
	if (rc)
		goto out;

	/* Start progress loop */
	while (1) {
		/* Sample progress */
		rc = hmr_progress_read(&result, fd, &bsg_req, &bsg_rsp);
		if (rc)
			goto out;

		hmr_output_progress(result, iter++, 1, "");

		/* Progress is 0 - completed */
		if (0 == result)
			break;
	}

out:
	hmr_output_footer(rc);
	return rc;
}

static int hmr_unit_start(int fd, int method)
{
	int rc;
	__u32 result;
	__u64 iter = 0;

	struct ufs_bsg_request bsg_req = {0};
	struct ufs_bsg_reply   bsg_rsp = {0};

	hmr_output_header("minimum", method);

	/* Start HMR loop */
	while (1) {
		/* Start unit refresh */
		rc = hmr_refresh_initiate(fd, &bsg_req, &bsg_rsp);
		if (rc)
			goto out;

		/* Verify completed */
		rc = hmr_unit_verify_completed(fd, &bsg_req, &bsg_rsp);
		if (rc)
			goto out;

		/* Read progress */
		rc = hmr_progress_read(&result, fd, &bsg_req, &bsg_rsp);
		if (rc)
			goto out;

		hmr_output_progress(result, iter++, 0, "");

		/* Progress is 0 - completed */
		if (0 == result)
			break;
	}

out:
	hmr_output_footer(rc);
	return rc;
}

int do_hmr(struct tool_options *opt)
{
	int rc;
	int fd;
	int (*hmr_job)(int, int);
	__u32 refresh_totcount;
	enum hmr_stage_skip stage_passer = 0;

	if (!opt || !opt->path)
		return -EHMR_INVAL;

	/* Open dev in subject */
	rc = hmr_dev_open(opt->path, &fd);
	if (rc)
		goto out;

	/* Make verifications prior to HMR */
	rc = hmr_precondition_verify(fd, opt, &refresh_totcount, &stage_passer);
	if (rc)
		goto out;

	/* Set HMR method: force or selective */
	if (!(stage_passer & HMR_SKIP_METHOD_SET)) {
		rc = hmr_method_set(fd, opt->hmr_method);
		if (rc)
			goto out;
	}

	/* Set HMR unit: minimum or full */
	if (!(stage_passer & HMR_SKIP_UNIT_SET)) {
		rc = hmr_unit_set(fd, opt->hmr_unit);
		if (rc)
			goto out;
	}

	/* Do the HMR job */
	hmr_job = opt->hmr_unit == HMR_UNIT_MIN ?
		&hmr_unit_start : &hmr_full_start;

	rc = (*hmr_job)(fd, opt->hmr_method);
	if (rc)
		goto out;

	/* Verify variables upon completion */
	rc = hmr_postcondition_verify(fd, refresh_totcount);
	if (rc)
		goto out;

out:
	return rc;
}

void hmr_help(char *tool_name)
{
	/* General use case description */
	printf("\n HMR command usage:\n");
	printf("\n\t%s hmr [-p] <path to device> ([-x] <method> [-y] <unit>)\n",
		tool_name);

	/* -p: mandatory, device path */
	printf("\n\t-p\t path - mandatory, ufs-bsg device path\n");

	/* -x: optional, HMR method */
	printf("\n\t-x\t method - optional, the default is %d\n",
		HMR_METHOD_SELECTIVE);
	printf("\t\t\t %-3d: %-25s\n",
		HMR_METHOD_FORCE, "force, refresh all blocks containing data");
	printf("\t\t\t %-3d: %-25s\n",
		HMR_METHOD_SELECTIVE, "selective, refresh marked blocks only");

	/* -y: optional, HMR unit */
	printf("\n\t-y\t unit - optional, the default is %d\n", HMR_UNIT_MIN);
	printf("\t\t\t %-3d: %-25s\n",
		HMR_UNIT_MIN, "minimum, perform HMR by minimum refresh units");
	printf("\t\t\t %-3d: %-25s\n",
		HMR_UNIT_FULL, "full, perform a full HMR cycle in one command");
}

