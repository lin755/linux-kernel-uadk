/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef _LINUX_UACCE_H
#define _LINUX_UACCE_H

#include <linux/cdev.h>
#include <uapi/misc/uacce.h>

#define UACCE_NAME		"uacce"

struct uacce_queue;
struct uacce_device;

/* uacce mode of the driver */
#define UACCE_MODE_NOUACCE	0 /* don't use uacce */
#define UACCE_MODE_UACCE	1 /* use uacce exclusively */

/* uacce queue file flag, requires different operation */
#define UACCE_QFRF_MAP		BIT(0)	/* map to current queue */
#define UACCE_QFRF_MMAP		BIT(1)	/* map to user space */
#define UACCE_QFRF_KMAP		BIT(2)	/* map to kernel space */
#define UACCE_QFRF_DMA		BIT(3)	/* use dma api for the region */
#define UACCE_QFRF_SELFMT	BIT(4)	/* self maintained qfr */

/**
 * struct uacce_qfile_region - structure of queue file region
 * @type: type of the qfr
 * @iova: iova share between user and device space
 * @pages: pages pointer of the qfr memory
 * @nr_pages: page numbers of the qfr memory
 * @prot: qfr protection flag
 * @flags: flags of qfr
 * @qs: list sharing the same region, for ss region
 * @kaddr: kernel addr of the qfr
 * @dma: dma address, if created by dma api
 */
struct uacce_qfile_region {
	enum uacce_qfrt type;
	unsigned long iova;
	struct page **pages;
	u32 nr_pages;
	u32 prot;
	u64 flags;
	struct list_head qs;
	void *kaddr;
	dma_addr_t dma;
};

/**
 * struct uacce_ops - uacce device operations
 * @get_available_instances:  get available instances left of the device
 * @get_queue: get a queue from the device
 * @put_queue: free a queue to the device
 * @start_queue: make the queue start work after get_queue
 * @stop_queue: make the queue stop work before put_queue
 * @is_q_updated: check whether the task is finished
 * @mask_notify: mask the task irq of queue
 * @mmap: mmap addresses of queue to user space
 * @reset: reset the uacce device
 * @reset_queue: reset the queue
 * @ioctl: ioctl for user space users of the queue
 */
struct uacce_ops {
	int (*get_available_instances)(struct uacce_device *uacce);
	int (*get_queue)(struct uacce_device *uacce, unsigned long arg,
			 struct uacce_queue **q);
	void (*put_queue)(struct uacce_queue *q);
	int (*start_queue)(struct uacce_queue *q);
	void (*stop_queue)(struct uacce_queue *q);
	int (*is_q_updated)(struct uacce_queue *q);
	void (*mask_notify)(struct uacce_queue *q, int event_mask);
	int (*mmap)(struct uacce_queue *q, struct vm_area_struct *vma,
		    struct uacce_qfile_region *qfr);
	int (*reset)(struct uacce_device *uacce);
	int (*reset_queue)(struct uacce_queue *q);
	long (*ioctl)(struct uacce_queue *q, unsigned int cmd,
		      unsigned long arg);
};

/**
 * struct uacce_interface
 * @name: the uacce device name.  Will show up in sysfs
 * @flags: uacce device attributes
 * @ops: pointer to the struct uacce_ops
 *
 * This structure is used for the uacce_register()
 */
struct uacce_interface {
	char name[32];
	unsigned int flags;
	struct uacce_ops *ops;
};

enum uacce_q_state {
	UACCE_Q_INIT,
	UACCE_Q_STARTED,
	UACCE_Q_ZOMBIE,
};

/**
 * struct uacce_queue
 * @uacce: pointer to uacce
 * @priv: private pointer
 * @wait: wait queue head
 * @pasid: pasid of the queue
 * @handle: iommu_sva handle return from iommu_sva_bind_device
 * @list: share list for qfr->qs
 * @mm: current->mm
 * @qfrs: pointer of qfr regions
 */
struct uacce_queue {
	struct uacce_device *uacce;
	void *priv;
	wait_queue_head_t wait;
	int pasid;
	struct iommu_sva *handle;
	struct list_head list;
	struct mm_struct *mm;
	struct uacce_qfile_region *qfrs[UACCE_QFRT_MAX];
	enum uacce_q_state state;
};

/**
 * struct uacce_device
 * @algs: supported algorithms
 * @api_ver: api version
 * @qf_pg_start: page start of the queue file regions
 * @ops: pointer to the struct uacce_ops
 * @pdev: pointer to the parent device
 * @is_vf: whether virtual function
 * @flags: uacce attributes
 * @dev_id: id of the uacce device
 * @prot: uacce protection flag
 * @cdev: cdev of the uacce
 * @dev: dev of the uacce
 * @priv: private pointer of the uacce
 */
struct uacce_device {
	const char *algs;
	const char *api_ver;
	unsigned long qf_pg_start[UACCE_QFRT_MAX];
	struct uacce_ops *ops;
	struct device *pdev;
	bool is_vf;
	u64 flags;
	u32 dev_id;
	u32 prot;
	struct cdev *cdev;
	struct device dev;
	void *priv;
};

struct uacce_device *uacce_register(struct device *parent,
				    struct uacce_interface *interface);
void uacce_unregister(struct uacce_device *uacce);

#endif /* _LINUX_UACCE_H */
