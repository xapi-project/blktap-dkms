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

#include <linux/device.h>
#include <linux/signal.h>
#include <linux/sched.h>
#include <linux/poll.h>
#include <linux/blkdev.h>
#include <linux/mman.h>

#include "blktap.h"

int blktap_ring_major;
static struct cdev blktap_ring_cdev;

 /* 
  * BLKTAP - immediately before the mmap area,
  * we have a bunch of pages reserved for shared memory rings.
  */
#define RING_PAGES 1

#define BLKTAP_INFO_SIZE_AT(_memb)			\
	offsetof(struct blktap_device_info, _memb) +	\
	sizeof(((struct blktap_device_info*)0)->_memb)

static void
blktap_ring_read_response(struct blktap *tap,
			  const struct blktap_ring_response *rsp)
{
	struct blktap_ring *ring = &tap->ring;
	struct blktap_request *request;
	int usr_idx, err;

	request = NULL;

	usr_idx = rsp->id;
	if (usr_idx < 0 || usr_idx >= BLKTAP_RING_SIZE) {
		err = -ERANGE;
		goto invalid;
	}

	request = ring->pending[usr_idx];

	if (!request) {
		err = -ESRCH;
		goto invalid;
	}

	if (rsp->operation != request->operation) {
		err = -EINVAL;
		goto invalid;
	}

	dev_dbg(ring->dev,
		"request %d [%p] response: %d\n",
		request->usr_idx, request, rsp->status);

	err = rsp->status == BLKTAP_RSP_OKAY ? 0 : -EIO;
end_request:
	blktap_device_end_request(tap, request, err);
	return;

invalid:
	dev_warn(ring->dev,
		 "invalid response, idx:%d status:%d op:%d/%d: err %d\n",
		 usr_idx, rsp->status,
		 rsp->operation, request->operation,
		 err);
	if (request)
		goto end_request;
}

static void
blktap_read_ring(struct blktap *tap)
{
	struct blktap_ring *ring = &tap->ring;
	struct blktap_ring_response rsp;
	RING_IDX rc, rp;

	down_read(&current->mm->mmap_sem);
	if (!ring->vma) {
		up_read(&current->mm->mmap_sem);
		return;
	}

	/* for each outstanding message on the ring  */
	rp = ring->ring.sring->rsp_prod;
	rmb();

	for (rc = ring->ring.rsp_cons; rc != rp; rc++) {
		memcpy(&rsp, RING_GET_RESPONSE(&ring->ring, rc), sizeof(rsp));
		blktap_ring_read_response(tap, &rsp);
	}

	ring->ring.rsp_cons = rc;

	up_read(&current->mm->mmap_sem);
}

#define MMAP_VADDR(_start, _req, _seg)				\
	((_start) +						\
	 ((_req) * BLKTAP_SEGMENT_MAX * BLKTAP_PAGE_SIZE) +	\
	 ((_seg) * BLKTAP_PAGE_SIZE))

static int blktap_ring_fault(struct vm_area_struct *vma, struct vm_fault *vmf)
{
	return VM_FAULT_SIGBUS;
}

static void
blktap_ring_fail_pending(struct blktap *tap)
{
	struct blktap_ring *ring = &tap->ring;
	struct blktap_request *request;
	int usr_idx;

	for (usr_idx = 0; usr_idx < BLKTAP_RING_SIZE; usr_idx++) {
		request = ring->pending[usr_idx];
		if (!request)
			continue;

		blktap_device_end_request(tap, request, -EIO);
	}
}

static void
blktap_ring_vm_close_sring(struct blktap *tap,
			   struct vm_area_struct *vma)
{
	struct blktap_ring *ring = &tap->ring;
	struct page *page = virt_to_page(ring->ring.sring);

	blktap_ring_fail_pending(tap);

	ClearPageReserved(page);
	__free_page(page);

	ring->vma = NULL;

	if (test_bit(BLKTAP_SHUTDOWN_REQUESTED, &tap->dev_inuse))
		blktap_control_destroy_tap(tap);
}

static void
blktap_ring_vm_close(struct vm_area_struct *vma)
{
	struct blktap *tap = vma->vm_private_data;

	dev_dbg(tap->ring.dev,
		"vm_close %lx-%lx (%lu) pgoff %lu\n",
		vma->vm_start, vma->vm_end, vma_pages(vma),
		vma->vm_pgoff);

	if (!vma->vm_pgoff)
		blktap_ring_vm_close_sring(tap, vma);
}

static struct vm_operations_struct blktap_ring_vm_operations = {
	.close    = blktap_ring_vm_close,
	.fault    = blktap_ring_fault,
};

int
blktap_ring_map_request(struct blktap *tap, struct file *filp,
			struct blktap_request *request)
{
	struct blktap_ring *ring = &tap->ring;
	unsigned long addr, len, pgoff;
	int read, write, prot, flags;

	write = request->operation == BLKTAP_OP_WRITE;
	read  = request->operation == BLKTAP_OP_READ;

	if (write)
		blktap_request_bounce(tap, request, write);

	prot  = PROT_READ;
	prot |= read ? PROT_WRITE : 0;

	flags = MAP_FIXED|MAP_SHARED;

	addr  = MMAP_VADDR(ring->user_vstart, request->usr_idx, 0);
	len   = request->nr_pages << PAGE_SHIFT;

	pgoff = 1 + request->usr_idx * BLKTAP_SEGMENT_MAX;

	addr = vm_mmap(filp, addr, len, prot, flags, pgoff << PAGE_SHIFT);

	return IS_ERR_VALUE(addr) ? addr : 0;
}

void
blktap_ring_unmap_request(struct blktap *tap,
			  struct blktap_request *request)
{
	struct blktap_ring *ring = &tap->ring;
	unsigned long addr, len;
	int read, err;

	read  = request->operation == BLKTAP_OP_READ;
	if (read)
		blktap_request_bounce(tap, request, !read);

	addr  = MMAP_VADDR(ring->user_vstart, request->usr_idx, 0);
	len   = request->nr_pages << PAGE_SHIFT;

	err = do_munmap(current->mm, addr, len);
	WARN_ON_ONCE(err);
}

void
blktap_ring_free_request(struct blktap *tap,
			 struct blktap_request *request)
{
	struct blktap_ring *ring = &tap->ring;

	ring->pending[request->usr_idx] = NULL;
	ring->n_pending--;

	blktap_request_free(tap, request);
}

struct blktap_request*
blktap_ring_make_request(struct blktap *tap)
{
	struct blktap_ring *ring = &tap->ring;
	struct blktap_request *request;
	int usr_idx;

	if (RING_FULL(&ring->ring))
		return ERR_PTR(-ENOSPC);

	request = blktap_request_alloc(tap);
	if (!request)
		return ERR_PTR(-ENOMEM);

	for (usr_idx = 0; usr_idx < BLKTAP_RING_SIZE; usr_idx++)
		if (!ring->pending[usr_idx])
			break;

	BUG_ON(usr_idx >= BLKTAP_RING_SIZE);

	request->tap     = tap;
	request->usr_idx = usr_idx;

	ring->pending[usr_idx] = request;
	ring->n_pending++;

	return request;
}

static int
blktap_ring_make_rw_request(struct blktap *tap,
			    struct blktap_request *request,
			    struct blktap_ring_request *breq)
{
	struct scatterlist *sg;
	unsigned int i, nsecs = 0;

	blktap_for_each_sg(sg, request, i) {
		struct blktap_segment *seg = &breq->u.rw.seg[i];
		int first, count;

		count = sg->length >> 9;
		first = sg->offset >> 9;

		seg->first_sect = first;
		seg->last_sect  = first + count - 1;

		nsecs += count;
	}

	breq->u.rw.sector_number = blk_rq_pos(request->rq);

	return nsecs;
}

static int
blktap_ring_make_tr_request(struct blktap *tap,
			    struct blktap_request *request,
			    struct blktap_ring_request *breq)
{
	struct bio *bio = request->rq->bio;
	unsigned int nsecs;

	breq->u.tr.nr_sectors    = nsecs = bio_sectors(bio);
	breq->u.tr.sector_number = bio->bi_sector;

	return nsecs;
}

void
blktap_ring_submit_request(struct blktap *tap,
			   struct blktap_request *request)
{
	struct blktap_ring *ring = &tap->ring;
	struct blktap_ring_request *breq;
	int nsecs;

	dev_dbg(ring->dev,
		"request %d [%p] submit\n", request->usr_idx, request);

	breq = RING_GET_REQUEST(&ring->ring, ring->ring.req_prod_pvt);

	breq->id            = request->usr_idx;
	breq->__pad         = 0;
	breq->operation     = request->operation;
	breq->nr_segments   = request->nr_pages;

	switch (breq->operation) {
	case BLKTAP_OP_READ:
		nsecs = blktap_ring_make_rw_request(tap, request, breq);

		tap->stats.st_rd_sect += nsecs;
		tap->stats.st_rd_req++;
		break;

	case BLKTAP_OP_WRITE:
		nsecs = blktap_ring_make_rw_request(tap, request, breq);

		tap->stats.st_wr_sect += nsecs;
		tap->stats.st_wr_req++;
		break;

	case BLKTAP_OP_FLUSH:
		breq->u.rw.sector_number = 0;
		tap->stats.st_fl_req++;
		break;

	case BLKTAP_OP_TRIM:
		nsecs = blktap_ring_make_tr_request(tap, request, breq);

		tap->stats.st_tr_sect += nsecs;
		tap->stats.st_tr_req++;
		break;
	default:
		BUG();
	}

	ring->ring.req_prod_pvt++;
}

static int
blktap_ring_open(struct inode *inode, struct file *filp)
{
	struct blktap *tap = NULL;
	int minor;

	minor = iminor(inode);

	if (minor < blktap_max_minor)
		tap = blktaps[minor];

	if (!tap)
		return -ENXIO;

	if (test_bit(BLKTAP_SHUTDOWN_REQUESTED, &tap->dev_inuse))
		return -ENXIO;

	if (tap->ring.task)
		return -EBUSY;

	filp->private_data = tap;
	tap->ring.task = current;

	return 0;
}

static int
blktap_ring_release(struct inode *inode, struct file *filp)
{
	struct blktap *tap = filp->private_data;

	blktap_device_destroy_sync(tap);

	tap->ring.task = NULL;

	if (test_bit(BLKTAP_SHUTDOWN_REQUESTED, &tap->dev_inuse))
		blktap_control_destroy_tap(tap);

	return 0;
}

static int
blktap_ring_mmap_request(struct blktap *tap,
			 struct vm_area_struct *vma)
{
	struct blktap_ring *ring = &tap->ring;
	struct blktap_request *request;
	int usr_idx, seg, err;
	unsigned long addr, n_segs;

	usr_idx  = vma->vm_pgoff - 1;
	seg      = usr_idx % BLKTAP_SEGMENT_MAX;
	usr_idx /= BLKTAP_SEGMENT_MAX;

	request = ring->pending[usr_idx];
	if (!request)
		return -EINVAL;

	n_segs = request->nr_pages - seg;
	n_segs = min(n_segs, vma_pages(vma));

	for (addr = vma->vm_start;
	     seg < n_segs;
	     seg++, addr += PAGE_SIZE) {
		struct page *page = request->pages[seg];

		dev_dbg(tap->ring.dev,
			"mmap request %d seg %d addr %lx\n",
			usr_idx, seg, addr);

		err = vm_insert_page(vma, addr, page);
		if (err)
			return err;
	}

	vma->vm_flags |= VM_DONTCOPY;
	vma->vm_flags |= VM_RESERVED;

	return 0;
}

static int
blktap_ring_mmap_sring(struct blktap *tap, struct vm_area_struct *vma)
{
	struct blktap_ring *ring = &tap->ring;
	struct blktap_sring *sring;
	struct page *page = NULL;
	int err;

	if (ring->vma)
		return -EBUSY;

	page = alloc_page(GFP_KERNEL|__GFP_ZERO);
	if (!page)
		return -ENOMEM;

	SetPageReserved(page);

	err = vm_insert_page(vma, vma->vm_start, page);
	if (err)
		goto fail;

	sring = page_address(page);
	SHARED_RING_INIT(sring);
	FRONT_RING_INIT(&ring->ring, sring, PAGE_SIZE);

	ring->ring_vstart = vma->vm_start;
	ring->user_vstart = ring->ring_vstart + PAGE_SIZE;

	vma->vm_private_data = tap;

	vma->vm_flags |= VM_DONTCOPY;
	vma->vm_flags |= VM_RESERVED;

	vma->vm_ops = &blktap_ring_vm_operations;

	ring->vma = vma;
	return 0;

fail:
	if (page) {
		ClearPageReserved(page);
		__free_page(page);
	}

	return err;
}

static int
blktap_ring_mmap(struct file *filp, struct vm_area_struct *vma)
{
	struct blktap *tap = filp->private_data;

	dev_dbg(tap->ring.dev,
		"mmap %lx-%lx (%lu) pgoff %lu\n",
		vma->vm_start, vma->vm_end, vma_pages(vma),
		vma->vm_pgoff);

	if (!vma->vm_pgoff)
		return blktap_ring_mmap_sring(tap, vma);

	return blktap_ring_mmap_request(tap, vma);
}

static long
blktap_ring_ioctl(struct file *filp,
		  unsigned int cmd, unsigned long arg)
{
	struct blktap *tap = filp->private_data;
	struct blktap_ring *ring = &tap->ring;
	void __user *ptr = (void *)arg;
	int err;

	BTDBG("%d: cmd: %u, arg: %lu\n", tap->minor, cmd, arg);

	if (!ring->vma || ring->vma->vm_mm != current->mm)
		return -EACCES;

	switch(cmd) {
	case BLKTAP_IOCTL_RESPOND:

		blktap_read_ring(tap);
		return 0;

	case BLKTAP_IOCTL_CREATE_DEVICE_COMPAT: {
		struct blktap_device_info info;
		struct blktap2_params params;

		if (copy_from_user(&params, ptr, sizeof(params)))
			return -EFAULT;

		info.capacity             = params.capacity;
		info.sector_size          = params.sector_size;
		info.flags                = 0;

		err = blktap_device_create(tap, &info);
		if (err)
			return err;

		if (params.name[0]) {
			strncpy(tap->name, params.name, sizeof(params.name));
			tap->name[sizeof(tap->name)-1] = 0;
		}

		return 0;
	}

	case BLKTAP_IOCTL_CREATE_DEVICE: {
		struct blktap_device_info __user *ptr = (void *)arg;
		struct blktap_device_info info;
		unsigned long mask;
		size_t base_sz, sz;

		mask  = BLKTAP_DEVICE_FLAG_RO;
		mask |= BLKTAP_DEVICE_FLAG_PSZ;
		mask |= BLKTAP_DEVICE_FLAG_FLUSH;
		mask |= BLKTAP_DEVICE_FLAG_TRIM;
		mask |= BLKTAP_DEVICE_FLAG_TRIM_RZ;

		memset(&info, 0, sizeof(info));
		sz = base_sz = BLKTAP_INFO_SIZE_AT(flags);

		if (copy_from_user(&info, ptr, sz))
			return -EFAULT;

		if ((info.flags & BLKTAP_DEVICE_FLAG_PSZ) != 0)
			sz = BLKTAP_INFO_SIZE_AT(phys_block_offset);

		if (info.flags & BLKTAP_DEVICE_FLAG_TRIM)
			sz = BLKTAP_INFO_SIZE_AT(trim_block_offset);

		if (sz > base_sz)
			if (copy_from_user(&info, ptr, sz))
				return -EFAULT;

		if (put_user(info.flags & mask, &ptr->flags))
			return -EFAULT;

		return blktap_device_create(tap, &info);
	}

	case BLKTAP_IOCTL_REMOVE_DEVICE:

		return blktap_device_destroy(tap);
	}

	return -ENOTTY;
}

static unsigned int blktap_ring_poll(struct file *filp, poll_table *wait)
{
	struct blktap *tap = filp->private_data;
	struct blktap_ring *ring = &tap->ring;
	int work;

	poll_wait(filp, &tap->pool->wait, wait);
	poll_wait(filp, &ring->poll_wait, wait);

	down_read(&current->mm->mmap_sem);
	if (ring->vma && tap->device.gd)
		blktap_device_run_queue(tap, filp);
	up_read(&current->mm->mmap_sem);

	work = ring->ring.req_prod_pvt - ring->ring.sring->req_prod;
	RING_PUSH_REQUESTS(&ring->ring);

	if (work ||
	    *BLKTAP_RING_MESSAGE(ring->ring.sring) ||
	    test_and_clear_bit(BLKTAP_DEVICE_CLOSED, &tap->dev_inuse))
		return POLLIN | POLLRDNORM;

	return 0;
}

static struct file_operations blktap_ring_file_operations = {
	.owner          = THIS_MODULE,
	.open           = blktap_ring_open,
	.release        = blktap_ring_release,
	.unlocked_ioctl = blktap_ring_ioctl,
	.mmap           = blktap_ring_mmap,
	.poll           = blktap_ring_poll,
};

void
blktap_ring_kick_user(struct blktap *tap)
{
	wake_up(&tap->ring.poll_wait);
}

int
blktap_ring_destroy(struct blktap *tap)
{
	struct blktap_ring *ring = &tap->ring;

	if (ring->task || ring->vma)
		return -EBUSY;

	return 0;
}

int
blktap_ring_create(struct blktap *tap)
{
	struct blktap_ring *ring = &tap->ring;

	init_waitqueue_head(&ring->poll_wait);
	ring->devno = MKDEV(blktap_ring_major, tap->minor);

	return 0;
}

size_t
blktap_ring_debug(struct blktap *tap, char *buf, size_t size)
{
	struct blktap_ring *ring = &tap->ring;
	char *s = buf, *end = buf + size;
	int usr_idx;

	s += snprintf(s, end - s,
		      "begin pending:%d\n", ring->n_pending);

	for (usr_idx = 0; usr_idx < BLKTAP_RING_SIZE; usr_idx++) {
		struct blktap_request *request;
		struct timeval t;

		request = ring->pending[usr_idx];
		if (!request)
			continue;

		jiffies_to_timeval(jiffies - request->rq->start_time, &t);

		s += snprintf(s, end - s,
			      "%02d: usr_idx:%02d "
			      "op:%x nr_pages:%02d time:%lu.%09lu\n",
			      usr_idx, request->usr_idx,
			      request->operation, request->nr_pages,
			      t.tv_sec, t.tv_usec);
	}

	s += snprintf(s, end - s, "end pending\n");

	return s - buf;
}


int __init
blktap_ring_init(void)
{
	dev_t dev = 0;
	int err;

	cdev_init(&blktap_ring_cdev, &blktap_ring_file_operations);
	blktap_ring_cdev.owner = THIS_MODULE;

	err = alloc_chrdev_region(&dev, 0, MAX_BLKTAP_DEVICE, "blktap2");
	if (err < 0) {
		BTERR("error registering ring devices: %d\n", err);
		return err;
	}

	err = cdev_add(&blktap_ring_cdev, dev, MAX_BLKTAP_DEVICE);
	if (err) {
		BTERR("error adding ring device: %d\n", err);
		unregister_chrdev_region(dev, MAX_BLKTAP_DEVICE);
		return err;
	}

	blktap_ring_major = MAJOR(dev);
	BTINFO("blktap ring major: %d\n", blktap_ring_major);

	return 0;
}

void
blktap_ring_exit(void)
{
	if (!blktap_ring_major)
		return;

	cdev_del(&blktap_ring_cdev);
	unregister_chrdev_region(MKDEV(blktap_ring_major, 0),
				 MAX_BLKTAP_DEVICE);

	blktap_ring_major = 0;
}
