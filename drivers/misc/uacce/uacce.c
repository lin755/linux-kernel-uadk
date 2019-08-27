// SPDX-License-Identifier: GPL-2.0-or-later
#include <linux/compat.h>
#include <linux/dma-iommu.h>
#include <linux/dma-mapping.h>
#include <linux/file.h>
#include <linux/idr.h>
#include <linux/irqdomain.h>
#include <linux/module.h>
#include <linux/poll.h>
#include <linux/sched/signal.h>
#include <linux/uacce.h>

static struct class *uacce_class;
static DEFINE_IDR(uacce_idr);
static dev_t uacce_devt;
static DEFINE_MUTEX(uacce_mutex); /* mutex to protect uacce */
static const struct file_operations uacce_fops;

/* match with enum uacce_qfrt */
static const char *const qfrt_str[] = {
	"mmio",
	"dko",
	"dus",
	"ss",
	"invalid"
};

static const char *uacce_qfrt_str(struct uacce_qfile_region *qfr)
{
	enum uacce_qfrt type = qfr->type;

	if (type > UACCE_QFRT_MAX)
		type = UACCE_QFRT_MAX;

	return qfrt_str[type];
}

/**
 * uacce_wake_up - Wake up the process who is waiting this queue
 * @q the accelerator queue to wake up
 */
void uacce_wake_up(struct uacce_queue *q)
{
	wake_up_interruptible(&q->wait);
}
EXPORT_SYMBOL_GPL(uacce_wake_up);

static int uacce_queue_map_qfr(struct uacce_queue *q,
			       struct uacce_qfile_region *qfr)
{
	struct device *dev = q->uacce->pdev;
	struct iommu_domain *domain = iommu_get_domain_for_dev(dev);
	int i, j, ret;

	if (!(qfr->flags & UACCE_QFRF_MAP) || (qfr->flags & UACCE_QFRF_DMA))
		return 0;

	if (!domain)
		return -ENODEV;

	for (i = 0; i < qfr->nr_pages; i++) {
		ret = iommu_map(domain, qfr->iova + i * PAGE_SIZE,
				page_to_phys(qfr->pages[i]),
				PAGE_SIZE, qfr->prot | q->uacce->prot);
		if (ret) {
			dev_err(dev, "iommu_map page %i fail %d\n", i, ret);
			goto err_with_map_pages;
		}
		get_page(qfr->pages[i]);
	}

	return 0;

err_with_map_pages:
	for (j = i - 1; j >= 0; j--) {
		iommu_unmap(domain, qfr->iova + j * PAGE_SIZE, PAGE_SIZE);
		put_page(qfr->pages[j]);
	}
	return ret;
}

static void uacce_queue_unmap_qfr(struct uacce_queue *q,
				  struct uacce_qfile_region *qfr)
{
	struct device *dev = q->uacce->pdev;
	struct iommu_domain *domain = iommu_get_domain_for_dev(dev);
	int i;

	if (!domain || !qfr)
		return;

	if (!(qfr->flags & UACCE_QFRF_MAP) || (qfr->flags & UACCE_QFRF_DMA))
		return;

	for (i = qfr->nr_pages - 1; i >= 0; i--) {
		iommu_unmap(domain, qfr->iova + i * PAGE_SIZE, PAGE_SIZE);
		put_page(qfr->pages[i]);
	}
}

static int uacce_qfr_alloc_pages(struct uacce_qfile_region *qfr)
{
	int i, j;

	qfr->pages = kcalloc(qfr->nr_pages, sizeof(*qfr->pages), GFP_ATOMIC);
	if (!qfr->pages)
		return -ENOMEM;

	for (i = 0; i < qfr->nr_pages; i++) {
		qfr->pages[i] = alloc_page(GFP_ATOMIC | __GFP_ZERO);
		if (!qfr->pages[i])
			goto err_with_pages;
	}

	return 0;

err_with_pages:
	for (j = i - 1; j >= 0; j--)
		put_page(qfr->pages[j]);

	kfree(qfr->pages);
	return -ENOMEM;
}

static void uacce_qfr_free_pages(struct uacce_qfile_region *qfr)
{
	int i;

	for (i = 0; i < qfr->nr_pages; i++)
		put_page(qfr->pages[i]);

	kfree(qfr->pages);
}

static inline int uacce_queue_mmap_qfr(struct uacce_queue *q,
				       struct uacce_qfile_region *qfr,
				       struct vm_area_struct *vma)
{
	int i, ret;

	for (i = 0; i < qfr->nr_pages; i++) {
		ret = remap_pfn_range(vma, vma->vm_start + (i << PAGE_SHIFT),
				      page_to_pfn(qfr->pages[i]), PAGE_SIZE,
				      vma->vm_page_prot);
		if (ret)
			return ret;
	}

	return 0;
}

static struct uacce_qfile_region *
uacce_create_region(struct uacce_queue *q, struct vm_area_struct *vma,
		    enum uacce_qfrt type, unsigned int flags)
{
	struct uacce_qfile_region *qfr;
	struct uacce *uacce = q->uacce;
	unsigned long vm_pgoff;
	int ret = -ENOMEM;

	qfr = kzalloc(sizeof(*qfr), GFP_ATOMIC);
	if (!qfr)
		return ERR_PTR(-ENOMEM);

	qfr->type = type;
	qfr->flags = flags;
	qfr->iova = vma->vm_start;
	qfr->nr_pages = vma_pages(vma);

	if (vma->vm_flags & VM_READ)
		qfr->prot |= IOMMU_READ;

	if (vma->vm_flags & VM_WRITE)
		qfr->prot |= IOMMU_WRITE;

	if (flags & UACCE_QFRF_SELFMT) {
		ret = uacce->ops->mmap(q, vma, qfr);
		if (ret)
			goto err_with_qfr;
		return qfr;
	}

	/* allocate memory */
	if (flags & UACCE_QFRF_DMA) {
		qfr->kaddr = dma_alloc_coherent(uacce->pdev,
						qfr->nr_pages << PAGE_SHIFT,
						&qfr->dma, GFP_KERNEL);
		if (!qfr->kaddr) {
			ret = -ENOMEM;
			goto err_with_qfr;
		}
	} else {
		ret = uacce_qfr_alloc_pages(qfr);
		if (ret)
			goto err_with_qfr;
	}

	/* map to device */
	ret = uacce_queue_map_qfr(q, qfr);
	if (ret)
		goto err_with_pages;

	/* mmap to user space */
	if (flags & UACCE_QFRF_MMAP) {
		if (flags & UACCE_QFRF_DMA) {

			/* dma_mmap_coherent() requires vm_pgoff as 0
			 * restore vm_pfoff to initial value for mmap()
			 */
			vm_pgoff = vma->vm_pgoff;
			vma->vm_pgoff = 0;
			ret = dma_mmap_coherent(uacce->pdev, vma, qfr->kaddr,
						qfr->dma,
						qfr->nr_pages << PAGE_SHIFT);
			vma->vm_pgoff = vm_pgoff;
		} else {
			ret = uacce_queue_mmap_qfr(q, qfr, vma);
		}

		if (ret)
			goto err_with_mapped_qfr;
	}

	return qfr;

err_with_mapped_qfr:
	uacce_queue_unmap_qfr(q, qfr);
err_with_pages:
	if (flags & UACCE_QFRF_DMA)
		dma_free_coherent(uacce->pdev, qfr->nr_pages << PAGE_SHIFT,
				  qfr->kaddr, qfr->dma);
	else
		uacce_qfr_free_pages(qfr);
err_with_qfr:
	kfree(qfr);

	return ERR_PTR(ret);
}

static void uacce_destroy_region(struct uacce_queue *q,
				 struct uacce_qfile_region *qfr)
{
	struct uacce *uacce = q->uacce;

	if (qfr->flags & UACCE_QFRF_DMA) {
		dma_free_coherent(uacce->pdev, qfr->nr_pages << PAGE_SHIFT,
				  qfr->kaddr, qfr->dma);
	} else if (qfr->pages) {
		if (qfr->flags & UACCE_QFRF_KMAP && qfr->kaddr) {
			vunmap(qfr->kaddr);
			qfr->kaddr = NULL;
		}

		uacce_qfr_free_pages(qfr);
	}
	kfree(qfr);
}

static long uacce_cmd_share_qfr(struct uacce_queue *tgt, int fd)
{
	struct file *filep;
	struct uacce_queue *src;
	int ret = -EINVAL;

	filep = fget(fd);
	if (!filep)
		return ret;

	if (filep->f_op != &uacce_fops)
		goto out_with_fd;

	src = filep->private_data;
	if (!src)
		goto out_with_fd;

	/* no share sva is needed if the dev can do fault-from-dev */
	if (tgt->uacce->flags & UACCE_DEV_FAULT_FROM_DEV)
		goto out_with_fd;

	mutex_lock(&uacce_mutex);
	if (!src->qfrs[UACCE_QFRT_SS] || tgt->qfrs[UACCE_QFRT_SS])
		goto out_with_lock;

	ret = uacce_queue_map_qfr(tgt, src->qfrs[UACCE_QFRT_SS]);
	if (ret)
		goto out_with_lock;

	tgt->qfrs[UACCE_QFRT_SS] = src->qfrs[UACCE_QFRT_SS];
	list_add(&tgt->list, &src->qfrs[UACCE_QFRT_SS]->qs);

out_with_lock:
	mutex_unlock(&uacce_mutex);
out_with_fd:
	fput(filep);
	return ret;
}

static int uacce_start_queue(struct uacce_queue *q)
{
	int ret, i, j;
	struct uacce_qfile_region *qfr;
	struct device *dev = &q->uacce->dev;

	/*
	 * map KMAP qfr to kernel
	 * vmap should be done in non-spinlocked context!
	 */
	for (i = 0; i < UACCE_QFRT_MAX; i++) {
		qfr = q->qfrs[i];
		if (qfr && (qfr->flags & UACCE_QFRF_KMAP) && !qfr->kaddr) {
			qfr->kaddr = vmap(qfr->pages, qfr->nr_pages, VM_MAP,
					  PAGE_KERNEL);
			if (!qfr->kaddr) {
				ret = -ENOMEM;
				dev_err(dev, "fail to kmap %s qfr(%d pages)\n",
					uacce_qfrt_str(qfr), qfr->nr_pages);
				goto err_with_vmap;
			}

		}
	}

	ret = q->uacce->ops->start_queue(q);
	if (ret < 0)
		goto err_with_vmap;

	atomic_set(&q->uacce->state, UACCE_ST_STARTED);
	return 0;

err_with_vmap:
	for (j = i; j >= 0; j--) {
		qfr = q->qfrs[j];
		if (qfr && qfr->kaddr) {
			vunmap(qfr->kaddr);
			qfr->kaddr = NULL;
		}
	}
	return ret;
}

static long uacce_fops_unl_ioctl(struct file *filep,
				 unsigned int cmd, unsigned long arg)
{
	struct uacce_queue *q = filep->private_data;
	struct uacce *uacce = q->uacce;

	switch (cmd) {
	case UACCE_CMD_SHARE_SVAS:
		return uacce_cmd_share_qfr(q, arg);

	case UACCE_CMD_START:
		return uacce_start_queue(q);

	default:
		if (!uacce->ops->ioctl) {
			dev_err(&uacce->dev,
				"ioctl cmd (%d) is not supported!\n", cmd);
			return -EINVAL;
		}

		return uacce->ops->ioctl(q, cmd, arg);
	}
}

#ifdef CONFIG_COMPAT
static long uacce_fops_compat_ioctl(struct file *filep,
				   unsigned int cmd, unsigned long arg)
{
	arg = (unsigned long)compat_ptr(arg);
	return uacce_fops_unl_ioctl(filep, cmd, arg);
}
#endif

static int uacce_dev_open_check(struct uacce *uacce)
{
	/*
	 * The device can be opened once if it dose not support pasid
	 */
	if (uacce->flags & UACCE_DEV_PASID)
		return 0;

	if (atomic_cmpxchg(&uacce->state, UACCE_ST_INIT, UACCE_ST_OPENED) !=
	    UACCE_ST_INIT) {
		dev_info(&uacce->dev, "this device can be openned only once\n");
		return -EBUSY;
	}

	return 0;
}

static int uacce_fops_open(struct inode *inode, struct file *filep)
{
	struct uacce_queue *q;
	struct iommu_sva *handle = NULL;
	struct uacce *uacce;
	int ret;
	int pasid = 0;

	uacce = idr_find(&uacce_idr, iminor(inode));
	if (!uacce)
		return -ENODEV;

	if (atomic_read(&uacce->state) == UACCE_ST_RST)
		return -EINVAL;

	if ((!uacce->ops->get_queue) || (!uacce->ops->start_queue))
		return -EINVAL;

	if (!try_module_get(uacce->pdev->driver->owner))
		return -ENODEV;

	ret = uacce_dev_open_check(uacce);
	if (ret)
		goto open_err;

#ifdef CONFIG_IOMMU_SVA
	if (uacce->flags & UACCE_DEV_PASID) {
		handle = iommu_sva_bind_device(uacce->pdev, current->mm, NULL);
		if (IS_ERR(handle))
			goto open_err;
		pasid = iommu_sva_get_pasid(handle);
	}
#endif
	ret = uacce->ops->get_queue(uacce, pasid, &q);
	if (ret < 0)
		goto open_err;

	q->pasid = pasid;
	q->handle = handle;
	q->uacce = uacce;
	q->mm = current->mm;
	memset(q->qfrs, 0, sizeof(q->qfrs));
	INIT_LIST_HEAD(&q->list);
	init_waitqueue_head(&q->wait);
	filep->private_data = q;
	mutex_lock(&uacce->q_lock);
	list_add(&q->q_dev, &uacce->qs);
	mutex_unlock(&uacce->q_lock);

	return 0;

open_err:
	module_put(uacce->pdev->driver->owner);
	return ret;
}

static int uacce_fops_release(struct inode *inode, struct file *filep)
{
	struct uacce_queue *q = filep->private_data;
	struct uacce_qfile_region *qfr;
	struct uacce *uacce = q->uacce;
	bool is_to_free_region;
	int free_pages = 0;
	int i;

	mutex_lock(&uacce->q_lock);
	list_del(&q->q_dev);
	mutex_unlock(&uacce->q_lock);

	if (atomic_read(&uacce->state) == UACCE_ST_STARTED &&
	    uacce->ops->stop_queue)
		uacce->ops->stop_queue(q);

	mutex_lock(&uacce_mutex);

	for (i = 0; i < UACCE_QFRT_MAX; i++) {
		qfr = q->qfrs[i];
		if (!qfr)
			continue;

		is_to_free_region = false;
		uacce_queue_unmap_qfr(q, qfr);
		if (i == UACCE_QFRT_SS) {
			list_del(&q->list);
			if (list_empty(&qfr->qs))
				is_to_free_region = true;
		} else
			is_to_free_region = true;

		if (is_to_free_region) {
			free_pages += qfr->nr_pages;
			uacce_destroy_region(q, qfr);
		}

		qfr = NULL;
	}

	mutex_unlock(&uacce_mutex);

	if (current->mm == q->mm) {
		down_write(&q->mm->mmap_sem);
		q->mm->data_vm -= free_pages;
		up_write(&q->mm->mmap_sem);
	}

#ifdef CONFIG_IOMMU_SVA
	if (uacce->flags & UACCE_DEV_PASID)
		iommu_sva_unbind_device(q->handle);
#endif

	if (uacce->ops->put_queue)
		uacce->ops->put_queue(q);

	atomic_set(&uacce->state, UACCE_ST_INIT);
	module_put(uacce->pdev->driver->owner);

	return 0;
}

static enum uacce_qfrt uacce_get_region_type(struct uacce *uacce,
					     struct vm_area_struct *vma)
{
	enum uacce_qfrt type = UACCE_QFRT_MAX;
	size_t next_start = UACCE_QFR_NA;
	int i;

	for (i = UACCE_QFRT_MAX - 1; i >= 0; i--) {
		if (vma->vm_pgoff >= uacce->qf_pg_start[i]) {
			type = i;
			break;
		}
	}

	switch (type) {
	case UACCE_QFRT_MMIO:
		if (!uacce->ops->mmap) {
			dev_err(&uacce->dev, "no driver mmap!\n");
			return UACCE_QFRT_MAX;
		}
		break;

	case UACCE_QFRT_DKO:
		if (uacce->flags & UACCE_DEV_PASID)
			return UACCE_QFRT_MAX;
		break;

	case UACCE_QFRT_DUS:
		break;

	case UACCE_QFRT_SS:
		/* todo: this can be valid to protect the process space */
		if (uacce->flags & UACCE_DEV_FAULT_FROM_DEV)
			return UACCE_QFRT_MAX;
		break;

	default:
		dev_err(&uacce->dev, "uacce bug (%d)!\n", type);
		return UACCE_QFRT_MAX;
	}

	/* make sure the mapping size is exactly the same as the region */
	if (type < UACCE_QFRT_SS) {
		for (i = type + 1; i < UACCE_QFRT_MAX; i++)
			if (uacce->qf_pg_start[i] != UACCE_QFR_NA) {
				next_start = uacce->qf_pg_start[i];
				break;
			}

		if (next_start == UACCE_QFR_NA) {
			dev_err(&uacce->dev, "uacce config error: SS offset set improperly\n");
			return UACCE_QFRT_MAX;
		}

		if (vma_pages(vma) !=
		    next_start - uacce->qf_pg_start[type]) {
			dev_err(&uacce->dev, "invalid mmap size (%ld vs %ld pages) for region %s.\n",
				vma_pages(vma),
				next_start - uacce->qf_pg_start[type],
				qfrt_str[type]);
			return UACCE_QFRT_MAX;
		}
	}

	return type;
}

static int uacce_fops_mmap(struct file *filep, struct vm_area_struct *vma)
{
	struct uacce_queue *q = filep->private_data;
	struct uacce *uacce = q->uacce;
	enum uacce_qfrt type = uacce_get_region_type(uacce, vma);
	struct uacce_qfile_region *qfr;
	unsigned int flags = 0;
	int ret;

	if (type == UACCE_QFRT_MAX)
		return -EINVAL;

	vma->vm_flags |= VM_DONTCOPY | VM_DONTEXPAND;

	mutex_lock(&uacce_mutex);

	/* fixme: if the region need no pages, we don't need to check it */
	if (q->mm->data_vm + vma_pages(vma) >
	    rlimit(RLIMIT_DATA) >> PAGE_SHIFT) {
		ret = -ENOMEM;
		goto out_with_lock;
	}

	if (q->qfrs[type]) {
		ret = -EBUSY;
		goto out_with_lock;
	}

	switch (type) {
	case UACCE_QFRT_MMIO:
		flags = UACCE_QFRF_SELFMT;
		break;

	case UACCE_QFRT_SS:
		if (atomic_read(&uacce->state) != UACCE_ST_STARTED) {
			ret = -EINVAL;
			goto out_with_lock;
		}

		flags = UACCE_QFRF_MAP | UACCE_QFRF_MMAP;

		break;

	case UACCE_QFRT_DKO:
		flags = UACCE_QFRF_MAP | UACCE_QFRF_KMAP;

		break;

	case UACCE_QFRT_DUS:
		if (uacce->flags & UACCE_DEV_PASID) {
			flags = UACCE_QFRF_SELFMT;
			break;
		}

		flags = UACCE_QFRF_MAP | UACCE_QFRF_MMAP;
		break;

	default:
		WARN_ON(&uacce->dev);
		break;
	}

	qfr = uacce_create_region(q, vma, type, flags);
	if (IS_ERR(qfr)) {
		ret = PTR_ERR(qfr);
		goto out_with_lock;
	}
	q->qfrs[type] = qfr;

	if (type == UACCE_QFRT_SS) {
		INIT_LIST_HEAD(&qfr->qs);
		list_add(&q->list, &q->qfrs[type]->qs);
	}

	mutex_unlock(&uacce_mutex);

	if (qfr->pages)
		q->mm->data_vm += qfr->nr_pages;

	return 0;

out_with_lock:
	mutex_unlock(&uacce_mutex);
	return ret;
}

static __poll_t uacce_fops_poll(struct file *file, poll_table *wait)
{
	struct uacce_queue *q = file->private_data;
	struct uacce *uacce = q->uacce;

	poll_wait(file, &q->wait, wait);
	if (uacce->ops->is_q_updated && uacce->ops->is_q_updated(q))
		return EPOLLIN | EPOLLRDNORM;

	return 0;
}

static const struct file_operations uacce_fops = {
	.owner		= THIS_MODULE,
	.open		= uacce_fops_open,
	.release	= uacce_fops_release,
	.unlocked_ioctl	= uacce_fops_unl_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl	= uacce_fops_compat_ioctl,
#endif
	.mmap		= uacce_fops_mmap,
	.poll		= uacce_fops_poll,
};

#define UACCE_FROM_CDEV_ATTR(dev) container_of(dev, struct uacce, dev)

static ssize_t id_show(struct device *dev,
		       struct device_attribute *attr, char *buf)
{
	struct uacce *uacce = UACCE_FROM_CDEV_ATTR(dev);

	return sprintf(buf, "%d\n", uacce->dev_id);
}

static ssize_t api_show(struct device *dev,
			struct device_attribute *attr, char *buf)
{
	struct uacce *uacce = UACCE_FROM_CDEV_ATTR(dev);

	return sprintf(buf, "%s\n", uacce->api_ver);
}

static ssize_t numa_distance_show(struct device *dev,
				  struct device_attribute *attr, char *buf)
{
	struct uacce *uacce = UACCE_FROM_CDEV_ATTR(dev);
	int distance;

	distance = node_distance(smp_processor_id(), uacce->pdev->numa_node);

	return sprintf(buf, "%d\n", abs(distance));
}

static ssize_t node_id_show(struct device *dev,
			    struct device_attribute *attr, char *buf)
{
	struct uacce *uacce = UACCE_FROM_CDEV_ATTR(dev);
	int node_id;

	node_id = dev_to_node(uacce->pdev);

	return sprintf(buf, "%d\n", node_id);
}

static ssize_t flags_show(struct device *dev,
			  struct device_attribute *attr, char *buf)
{
	struct uacce *uacce = UACCE_FROM_CDEV_ATTR(dev);

	return sprintf(buf, "%d\n", uacce->flags);
}

static ssize_t available_instances_show(struct device *dev,
					struct device_attribute *attr,
					char *buf)
{
	struct uacce *uacce = UACCE_FROM_CDEV_ATTR(dev);
	int val = 0;

	if (uacce->ops->get_available_instances)
		val = uacce->ops->get_available_instances(uacce);

	return sprintf(buf, "%d\n", val);
}

static ssize_t algorithms_show(struct device *dev,
			       struct device_attribute *attr, char *buf)
{
	struct uacce *uacce = UACCE_FROM_CDEV_ATTR(dev);

	return sprintf(buf, "%s", uacce->algs);
}

static ssize_t qfrs_offset_show(struct device *dev,
				struct device_attribute *attr, char *buf)
{
	struct uacce *uacce = UACCE_FROM_CDEV_ATTR(dev);
	int i, ret;
	unsigned long offset;

	for (i = 0, ret = 0; i < UACCE_QFRT_MAX; i++) {
		offset = uacce->qf_pg_start[i];
		if (offset != UACCE_QFR_NA)
			offset = offset << PAGE_SHIFT;
		if (i == UACCE_QFRT_SS)
			break;
		ret += sprintf(buf + ret, "%lu\t", offset);
	}
	ret += sprintf(buf + ret, "%lu\n", offset);

	return ret;
}

static DEVICE_ATTR_RO(id);
static DEVICE_ATTR_RO(api);
static DEVICE_ATTR_RO(numa_distance);
static DEVICE_ATTR_RO(node_id);
static DEVICE_ATTR_RO(flags);
static DEVICE_ATTR_RO(available_instances);
static DEVICE_ATTR_RO(algorithms);
static DEVICE_ATTR_RO(qfrs_offset);

static struct attribute *uacce_dev_attrs[] = {
	&dev_attr_id.attr,
	&dev_attr_api.attr,
	&dev_attr_node_id.attr,
	&dev_attr_numa_distance.attr,
	&dev_attr_flags.attr,
	&dev_attr_available_instances.attr,
	&dev_attr_algorithms.attr,
	&dev_attr_qfrs_offset.attr,
	NULL,
};

static const struct attribute_group uacce_dev_attr_group = {
	.attrs	= uacce_dev_attrs,
};

static const struct attribute_group *uacce_dev_attr_groups[] = {
	&uacce_dev_attr_group,
	NULL
};

static int uacce_create_chrdev(struct uacce *uacce)
{
	int ret;

	ret = idr_alloc(&uacce_idr, uacce, 0, 0, GFP_KERNEL);
	if (ret < 0)
		return ret;

	cdev_init(&uacce->cdev, &uacce_fops);
	uacce->dev_id = ret;
	uacce->cdev.owner = THIS_MODULE;
	device_initialize(&uacce->dev);
	uacce->dev.devt = MKDEV(MAJOR(uacce_devt), uacce->dev_id);
	uacce->dev.class = uacce_class;
	uacce->dev.groups = uacce_dev_attr_groups;
	uacce->dev.parent = uacce->pdev;
	dev_set_name(&uacce->dev, "%s-%d", uacce->drv_name, uacce->dev_id);
	ret = cdev_device_add(&uacce->cdev, &uacce->dev);
	if (ret)
		goto err_with_idr;

	dev_dbg(&uacce->dev, "create uacce minior=%d\n", uacce->dev_id);
	return 0;

err_with_idr:
	idr_remove(&uacce_idr, uacce->dev_id);
	return ret;
}

static void uacce_destroy_chrdev(struct uacce *uacce)
{
	cdev_device_del(&uacce->cdev, &uacce->dev);
	idr_remove(&uacce_idr, uacce->dev_id);
}

static int uacce_dev_match(struct device *dev, void *data)
{
	if (dev->parent == data)
		return -EBUSY;

	return 0;
}

/* Borrowed from VFIO to fix msi translation */
static bool uacce_iommu_has_sw_msi(struct iommu_group *group,
				   phys_addr_t *base)
{
	struct list_head group_resv_regions;
	struct iommu_resv_region *region, *next;
	bool ret = false;

	INIT_LIST_HEAD(&group_resv_regions);
	iommu_get_group_resv_regions(group, &group_resv_regions);
	list_for_each_entry(region, &group_resv_regions, list) {
		pr_debug("uacce: find a resv region (%d) on %llx\n",
			 region->type, region->start);

		/*
		 * The presence of any 'real' MSI regions should take
		 * precedence over the software-managed one if the
		 * IOMMU driver happens to advertise both types.
		 */
		if (region->type == IOMMU_RESV_MSI) {
			ret = false;
			break;
		}

		if (region->type == IOMMU_RESV_SW_MSI) {
			*base = region->start;
			ret = true;
		}
	}
	list_for_each_entry_safe(region, next, &group_resv_regions, list)
		kfree(region);
	return ret;
}

static int uacce_set_iommu_domain(struct uacce *uacce)
{
	struct iommu_domain *domain;
	struct iommu_group *group;
	struct device *dev = uacce->pdev;
	bool resv_msi;
	phys_addr_t resv_msi_base = 0;
	int ret;

	if (uacce->flags & UACCE_DEV_PASID)
		return 0;

	/*
	 * We don't support multiple register for the same dev if no pasid
	 */
	ret = class_for_each_device(uacce_class, NULL, uacce->pdev,
				    uacce_dev_match);
	if (ret)
		return ret;

	/* allocate and attach a unmanged domain */
	domain = iommu_domain_alloc(uacce->pdev->bus);
	if (!domain) {
		dev_err(&uacce->dev, "cannot get domain for iommu\n");
		return -ENODEV;
	}

	ret = iommu_attach_device(domain, uacce->pdev);
	if (ret)
		goto err_with_domain;

	if (iommu_capable(dev->bus, IOMMU_CAP_CACHE_COHERENCY))
		uacce->prot |= IOMMU_CACHE;

	group = iommu_group_get(dev);
	if (!group) {
		ret = -EINVAL;
		goto err_with_domain;
	}

	resv_msi = uacce_iommu_has_sw_msi(group, &resv_msi_base);
	iommu_group_put(group);

	if (resv_msi) {
		if (!irq_domain_check_msi_remap() &&
		    !iommu_capable(dev->bus, IOMMU_CAP_INTR_REMAP)) {
			dev_warn(dev, "No interrupt remapping support!");
			ret = -EPERM;
			goto err_with_domain;
		}

		ret = iommu_get_msi_cookie(domain, resv_msi_base);
		if (ret)
			goto err_with_domain;
	}

	return 0;

err_with_domain:
	iommu_domain_free(domain);
	return ret;
}

static void uacce_unset_iommu_domain(struct uacce *uacce)
{
	struct iommu_domain *domain;

	if (uacce->flags & UACCE_DEV_PASID)
		return;

	domain = iommu_get_domain_for_dev(uacce->pdev);
	if (!domain) {
		dev_err(&uacce->dev, "bug: no domain attached to device\n");
		return;
	}

	iommu_detach_device(domain, uacce->pdev);
	iommu_domain_free(domain);
}

/**
 *	uacce_register - register an accelerator
 *	@uacce: the accelerator structure
 */
struct uacce *uacce_register(struct device *parent,
			     struct uacce_interface *interface)
{
	int ret, i;
	struct uacce *uacce;
	unsigned int flags = interface->flags;

	/* if dev support fault-from-dev, it should support pasid */
	if ((flags & UACCE_DEV_FAULT_FROM_DEV) && !(flags & UACCE_DEV_PASID)) {
		dev_warn(parent, "SVM/SAV device should support PASID\n");
		return ERR_PTR(-EINVAL);
	}

#ifdef CONFIG_IOMMU_SVA
	if (flags & UACCE_DEV_PASID) {
		ret = iommu_dev_enable_feature(parent, IOMMU_DEV_FEAT_SVA);
		if (ret)
			flags &= ~(UACCE_DEV_FAULT_FROM_DEV |
				   UACCE_DEV_PASID);
	}
#endif
	uacce = kzalloc(sizeof(struct uacce), GFP_KERNEL);
	if (!uacce)
		return ERR_PTR(-ENOMEM);

	uacce->pdev = parent;
	uacce->flags = flags;
	uacce->ops = interface->ops;
	uacce->drv_name = interface->name;

	for (i = 0; i < UACCE_QFRT_MAX; i++)
		uacce->qf_pg_start[i] = UACCE_QFR_NA;

	ret = uacce_set_iommu_domain(uacce);
	if (ret)
		goto err_free;

	mutex_lock(&uacce_mutex);

	ret = uacce_create_chrdev(uacce);
	if (ret)
		goto err_with_lock;

	atomic_set(&uacce->state, UACCE_ST_INIT);
	INIT_LIST_HEAD(&uacce->qs);
	mutex_init(&uacce->q_lock);
	mutex_unlock(&uacce_mutex);

	return uacce;

err_with_lock:
	mutex_unlock(&uacce_mutex);
err_free:
	kfree(uacce);
	return ERR_PTR(ret);
}
EXPORT_SYMBOL_GPL(uacce_register);

/**
 * uacce_unregister - unregisters a uacce
 * @uacce: the accelerator to unregister
 *
 * Unregister an accelerator that wat previously successully registered with
 * uacce_register().
 */
void uacce_unregister(struct uacce *uacce)
{
	mutex_lock(&uacce_mutex);

#ifdef CONFIG_IOMMU_SVA
	if (uacce->flags & UACCE_DEV_PASID)
		iommu_dev_disable_feature(uacce->pdev, IOMMU_DEV_FEAT_SVA);
#endif
	uacce_unset_iommu_domain(uacce);

	uacce_destroy_chrdev(uacce);

	mutex_unlock(&uacce_mutex);

	kfree(uacce);
}
EXPORT_SYMBOL_GPL(uacce_unregister);

static int __init uacce_init(void)
{
	int ret;

	uacce_class = class_create(THIS_MODULE, UACCE_NAME);
	if (IS_ERR(uacce_class)) {
		ret = PTR_ERR(uacce_class);
		goto err;
	}

	ret = alloc_chrdev_region(&uacce_devt, 0, MINORMASK, UACCE_NAME);
	if (ret)
		goto err_with_class;

	pr_info("uacce init with major number:%d\n", MAJOR(uacce_devt));

	return 0;

err_with_class:
	class_destroy(uacce_class);
err:
	return ret;
}

static __exit void uacce_exit(void)
{
	unregister_chrdev_region(uacce_devt, MINORMASK);
	class_destroy(uacce_class);
	idr_destroy(&uacce_idr);
}

subsys_initcall(uacce_init);
module_exit(uacce_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Hisilicon Tech. Co., Ltd.");
MODULE_DESCRIPTION("Accelerator interface for Userland applications");
