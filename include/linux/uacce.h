/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef _LINUX_UACCE_H
#define _LINUX_UACCE_H

#include <linux/cdev.h>
#include <uapi/misc/uacce/uacce.h>

#define UACCE_NAME		"uacce"
#define UACCE_MAX_REGION	16
#define UACCE_MAX_NAME_SIZE	64

struct uacce_queue;
struct uacce_device;

/**
 * struct uacce_qfile_region - structure of queue file region
 * @type: type of the qfr
 */
struct uacce_qfile_region {
	enum uacce_qfrt type;
};

/**
 * struct uacce_ops - uacce device operations
 * @get_available_instances:  get available instances left of the device
 * @get_queue: get a queue from the device
 * @put_queue: free a queue to the device
 * @start_queue: make the queue start work after get_queue
 * @stop_queue: make the queue stop work before put_queue
 * @is_q_updated: check whether the task is finished
 * @mmap: mmap addresses of queue to user space
 * @ioctl: ioctl for user space users of the queue
 */
struct uacce_ops {
	int (*get_available_instances)(struct uacce_device *uacce);
	int (*get_queue)(struct uacce_device *uacce, unsigned long arg,
			 struct uacce_queue *q);
	void (*put_queue)(struct uacce_queue *q);
	int (*start_queue)(struct uacce_queue *q);
	void (*stop_queue)(struct uacce_queue *q);
	int (*is_q_updated)(struct uacce_queue *q);
	int (*mmap)(struct uacce_queue *q, struct vm_area_struct *vma,
		    struct uacce_qfile_region *qfr);
	long (*ioctl)(struct uacce_queue *q, unsigned int cmd,
		      unsigned long arg);
};

/**
 * struct uacce_interface - interface required for uacce_register()
 * @name: the uacce device name.  Will show up in sysfs
 * @flags: uacce device attributes
 * @ops: pointer to the struct uacce_ops
 */
struct uacce_interface {
	char name[UACCE_MAX_NAME_SIZE];
	unsigned int flags;
	const struct uacce_ops *ops;
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
 * @pid: pid of the process using the queue
 * @handle: iommu_sva handle return from iommu_sva_bind_device
 * @list: queue list
 * @qfrs: pointer of qfr regions
 * @state: queue state machine
 */
struct uacce_queue {
	struct uacce_device *uacce;
	void *priv;
	wait_queue_head_t wait;
	int pasid;
	pid_t pid;
	struct iommu_sva *handle;
	struct list_head list;
	struct uacce_qfile_region *qfrs[UACCE_MAX_REGION];
	enum uacce_q_state state;
};

/**
 * struct uacce_device
 * @algs: supported algorithms
 * @api_ver: api version
 * @qf_pg_size: page size of the queue file regions
 * @ops: pointer to the struct uacce_ops
 * @parent: pointer to the parent device
 * @is_vf: whether virtual function
 * @flags: uacce attributes
 * @dev_id: id of the uacce device
 * @prot: uacce protection flag
 * @cdev: cdev of the uacce
 * @dev: dev of the uacce
 * @priv: private pointer of the uacce
 * @qs: list head of queue->list
 * @q_lock: lock for qs
 */
struct uacce_device {
	const char *algs;
	const char *api_ver;
	const struct uacce_ops *ops;
	unsigned long qf_pg_size[UACCE_MAX_REGION];
	struct device *parent;
	bool is_vf;
	u32 flags;
	u32 dev_id;
	u32 prot;
	struct cdev *cdev;
	struct device dev;
	void *priv;
	struct list_head qs;
	struct mutex q_lock;
};

#if IS_ENABLED(CONFIG_UACCE)

struct uacce_device *uacce_register(struct device *parent,
				    struct uacce_interface *interface);
void uacce_unregister(struct uacce_device *uacce);

#else /* CONFIG_UACCE */

static inline
struct uacce_device *uacce_register(struct device *parent,
				    struct uacce_interface *interface)
{
	return ERR_PTR(-ENODEV);
}

static inline void uacce_unregister(struct uacce_device *uacce) {}

#endif /* CONFIG_UACCE */

#endif /* _LINUX_UACCE_H */
