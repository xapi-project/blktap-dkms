/*
 * Copyright (c) 2011, XenSource Inc.
 * All rights reserved.
 */

#ifndef _LINUX_BLKTAP_H
#define _LINUX_BLKTAP_H

/*
 * Control
 */

#define BLKTAP_IOCTL_RESPOND        1
#define BLKTAP_IOCTL_ALLOC_TAP      200
#define BLKTAP_IOCTL_FREE_TAP       201
#define BLKTAP_IOCTL_CREATE_DEVICE  208
#define BLKTAP_IOCTL_REMOVE_DEVICE  207

#define BLKTAP_DEVICE_FLAG_RO       0x00000001UL /* disk is R/O */
#define BLKTAP_DEVICE_FLAG_PSZ      0x00000002UL /* physical sector size */
#define BLKTAP_DEVICE_FLAG_FLUSH    0x00000004UL /* supports FLUSH */
#define BLKTAP_DEVICE_FLAG_TRIM     0x00000008UL /* supports TRIM */
#define BLKTAP_DEVICE_FLAG_TRIM_RZ  0x00000010UL /* trimmed data reads zero */

struct blktap_info {
	unsigned int            ring_major;
	unsigned int            bdev_major;
	unsigned int            ring_minor;
};

struct blktap_device_info {
	unsigned long long      capacity;
	unsigned int            sector_size;
	unsigned long           flags;
	unsigned int            phys_block_size;
	unsigned int            phys_block_offset;
	unsigned int            trim_block_size;
	unsigned int            trim_block_offset;
};

/*
 * I/O ring
 */

#ifdef __KERNEL__
#define BLKTAP_PAGE_SIZE PAGE_SIZE
#endif

#include <xen/interface/io/ring.h>

struct blktap_segment {
	uint32_t                __pad;
	uint8_t                 first_sect;
	uint8_t                 last_sect;
};

#define BLKTAP_OP_READ          0
#define BLKTAP_OP_WRITE         1
#define BLKTAP_OP_FLUSH         2
#define BLKTAP_OP_TRIM          3

#define BLKTAP_SEGMENT_MAX      11

struct blktap_ring_rw_request {
	uint64_t                sector_number;
	struct blktap_segment   seg[BLKTAP_SEGMENT_MAX];
};

struct blktap_ring_tr_request {
	uint64_t                sector_number;
	uint64_t                nr_sectors;
};

struct blktap_ring_request {
	uint8_t                 operation;
	uint8_t                 nr_segments;
	uint16_t                __pad;
	uint64_t                id;
	union {
		struct blktap_ring_rw_request   rw;
		struct blktap_ring_tr_request   tr;
	} u;
};

#define BLKTAP_RSP_EOPNOTSUPP  -2
#define BLKTAP_RSP_ERROR       -1
#define BLKTAP_RSP_OKAY         0

struct blktap_ring_response {
	uint64_t                id;
	uint8_t                 operation;
	int16_t                 status;
};

DEFINE_RING_TYPES(blktap,
		  struct blktap_ring_request,
		  struct blktap_ring_response);

#define BLKTAP_RING_SIZE						\
	((int)__RD32((BLKTAP_PAGE_SIZE -				\
		      (size_t)&((struct blktap_sring*)0)->ring) /	\
		     sizeof(((struct blktap_sring *)0)->ring[0])))

/*
 * Ring messages + old ioctls (DEPRECATED)
 */

#define BLKTAP_RING_MESSAGE(_sring) \
	((uint8_t*)(&(_sring)->rsp_event + 1))
#define BLKTAP_RING_MESSAGE_CLOSE   3
#define BLKTAP_IOCTL_CREATE_DEVICE_COMPAT 202
#define BLKTAP_NAME_MAX 256

struct blktap2_params {
	char               name[BLKTAP_NAME_MAX];
	unsigned long long capacity;
	unsigned long      sector_size;
};

#endif /* _LINUX_BLKTAP_H */
