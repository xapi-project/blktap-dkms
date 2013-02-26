/*
 *
 * Copyright (C) 2011 Citrix Systems Inc.
 *
 * This file is part of Blktap2.
 *
 * Blktap2 is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation.
 *
 * Blktap2 is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License version 2 for more details.
 *
 * You should have received a copy of the GNU General Public License
 * version 2 along with Blktap2.  If not, see 
 * <http://www.gnu.org/licenses/>.
 *
 *
 */

#ifndef _BLKTAP_H_
#define _BLKTAP_H_

#include <linux/module.h>
#include <linux/mm.h>
#include <linux/fs.h>
#include <linux/cdev.h>
#include <linux/init.h>
#include <linux/scatterlist.h>
#include <linux/mutex.h>
#include "linux-blktap.h"

extern int blktap_debug_level;
extern int blktap_ring_major;
extern int blktap_device_major;

#define BTPRINTK(level, tag, force, _f, _a...)				\
	do {								\
		if (blktap_debug_level > level &&			\
		    (force || printk_ratelimit()))			\
			printk(tag "%s: " _f, __func__, ##_a);		\
	} while (0)

#define BTDBG(_f, _a...)             BTPRINTK(8, KERN_DEBUG, 1, _f, ##_a)
#define BTINFO(_f, _a...)            BTPRINTK(0, KERN_INFO, 0, _f, ##_a)
#define BTWARN(_f, _a...)            BTPRINTK(0, KERN_WARNING, 0, _f, ##_a)
#define BTERR(_f, _a...)             BTPRINTK(0, KERN_ERR, 0, _f, ##_a)

#define MAX_BLKTAP_DEVICE            1024

#define BLKTAP_DEVICE                4
#define BLKTAP_DEVICE_CLOSED         5
#define BLKTAP_SHUTDOWN_REQUESTED    8

#define BLKTAP_REQUEST_FREE          0
#define BLKTAP_REQUEST_PENDING       1

struct blktap_device {
	spinlock_t                     lock;
	struct gendisk                *gd;
};

struct blktap_request;

struct blktap_ring {
	struct task_struct            *task;

	struct vm_area_struct         *vma;
	struct mutex                   vma_lock;
	struct blktap_front_ring       ring;
	unsigned long                  ring_vstart;
	unsigned long                  user_vstart;

	int                            n_pending;
	struct blktap_request         *pending[BLKTAP_RING_SIZE];

	wait_queue_head_t              poll_wait;

	dev_t                          devno;
	struct device                 *dev;
};

struct blktap_statistics {
	unsigned long                  st_print;
	int                            st_rd_req;
	int                            st_wr_req;
	int                            st_tr_req;
	int                            st_oo_req;
	int                            st_fl_req;
	int                            st_rd_sect;
	int                            st_wr_sect;
	int                            st_tr_sect;
	s64                            st_rd_cnt;
	s64                            st_rd_sum_usecs;
	s64                            st_rd_max_usecs;
	s64                            st_wr_cnt;
	s64                            st_wr_sum_usecs;
	s64                            st_wr_max_usecs;	
};

struct blktap_request {
	struct blktap                 *tap;
	struct request                *rq;
	int                            usr_idx;

	int                            operation;

	struct scatterlist             sg_table[BLKTAP_SEGMENT_MAX];
	struct page                   *pages[BLKTAP_SEGMENT_MAX];
	int                            nr_pages;
};

#define blktap_for_each_sg(_sg, _req, _i)	\
	for (_sg = (_req)->sg_table, _i = 0;	\
	     _i < (_req)->nr_pages;		\
	     (_sg)++, (_i)++)

struct blktap {
	int                            minor;
	unsigned long                  dev_inuse;

	struct blktap_ring             ring;
	struct blktap_device           device;
	struct blktap_page_pool       *pool;

	wait_queue_head_t              remove_wait;
	struct work_struct             remove_work;
	char                           name[BLKTAP_NAME_MAX];

	struct blktap_statistics       stats;
};

struct blktap_page_pool {
	struct mempool_s              *bufs;
	spinlock_t                     lock;
	struct kobject                 kobj;
	wait_queue_head_t              wait;
};

extern struct mutex blktap_lock;
extern struct blktap **blktaps;
extern int blktap_max_minor;

int blktap_control_destroy_tap(struct blktap *);
size_t blktap_control_debug(struct blktap *, char *, size_t);

int blktap_ring_init(void);
void blktap_ring_exit(void);
size_t blktap_ring_debug(struct blktap *, char *, size_t);
int blktap_ring_create(struct blktap *);
int blktap_ring_destroy(struct blktap *);
struct blktap_request *blktap_ring_make_request(struct blktap *);
void blktap_ring_free_request(struct blktap *,struct blktap_request *);
void blktap_ring_submit_request(struct blktap *, struct blktap_request *);
int blktap_ring_map_request(struct blktap *, struct file *, struct blktap_request *);
void blktap_ring_unmap_request(struct blktap *, struct blktap_request *);
void blktap_ring_set_message(struct blktap *, int);
void blktap_ring_kick_user(struct blktap *);

int blktap_sysfs_init(void);
void blktap_sysfs_exit(void);
int blktap_sysfs_create(struct blktap *);
void blktap_sysfs_destroy(struct blktap *);

int blktap_device_init(void);
void blktap_device_exit(void);
size_t blktap_device_debug(struct blktap *, char *, size_t);
int blktap_device_create(struct blktap *, struct blktap_device_info *);
int blktap_device_destroy(struct blktap *);
void blktap_device_destroy_sync(struct blktap *);
void blktap_device_run_queue(struct blktap *, struct file *);
void blktap_device_end_request(struct blktap *, struct blktap_request *, int);

int blktap_page_pool_init(struct kobject *);
void blktap_page_pool_exit(void);
struct blktap_page_pool *blktap_page_pool_get(const char *);

size_t blktap_request_debug(struct blktap *, char *, size_t);
struct blktap_request *blktap_request_alloc(struct blktap *);
int blktap_request_get_pages(struct blktap *, struct blktap_request *, int);
void blktap_request_free(struct blktap *, struct blktap_request *);
void blktap_request_bounce(struct blktap *, struct blktap_request *, int);


#endif
