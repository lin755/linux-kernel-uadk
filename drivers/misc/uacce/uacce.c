// SPDX-License-Identifier: GPL-2.0-or-later
#include <linux/compat.h>
#include <linux/dma-iommu.h>
#include <linux/module.h>
#include <linux/poll.h>
#include <linux/uacce.h>

static struct class *uacce_class;
static dev_t uacce_devt;
static DEFINE_MUTEX(uacce_mutex);
static DEFINE_XARRAY_ALLOC(uacce_xa);

static int uacce_start_queue(struct uacce_queue *q)
{
	int ret = 0;

	mutex_lock(&uacce_mutex);

	if (q->state != UACCE_Q_INIT) {
		ret = -EINVAL;
		goto out_with_lock;
	}

	if (q->uacce->ops->start_queue) {
		ret = q->uacce->ops->start_queue(q);
		if (ret < 0)
			goto out_with_lock;
	}

	q->state = UACCE_Q_STARTED;

out_with_lock:
	mutex_unlock(&uacce_mutex);

	return ret;
}

static int uacce_put_queue(struct uacce_queue *q)
{
	struct uacce_device *uacce = q->uacce;

	mutex_lock(&uacce_mutex);

	if (q->state == UACCE_Q_ZOMBIE)
		goto out;

	if ((q->state == UACCE_Q_STARTED) && uacce->ops->stop_queue)
		uacce->ops->stop_queue(q);

	if ((q->state == UACCE_Q_INIT || q->state == UACCE_Q_STARTED) &&
	     uacce->ops->put_queue)
		uacce->ops->put_queue(q);

	q->state = UACCE_Q_ZOMBIE;
out:
	mutex_unlock(&uacce_mutex);

	return 0;
}

static long uacce_fops_unl_ioctl(struct file *filep,
				 unsigned int cmd, unsigned long arg)
{
	struct uacce_queue *q = filep->private_data;
	struct uacce_device *uacce = q->uacce;

	switch (cmd) {
	case UACCE_CMD_START_Q:
		return uacce_start_queue(q);

	case UACCE_CMD_PUT_Q:
		return uacce_put_queue(q);

	default:
		if (!uacce->ops->ioctl)
			return -EINVAL;

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

static int uacce_sva_exit(struct device *dev, struct iommu_sva *handle,
			  void *data)
{
	struct uacce_device *uacce = data;
	struct uacce_queue *q;

	mutex_lock(&uacce->q_lock);
	list_for_each_entry(q, &uacce->qs, list) {
		if (q->pid == task_pid_nr(current))
			uacce_put_queue(q);
	}
	mutex_unlock(&uacce->q_lock);

	return 0;
}

static struct iommu_sva_ops uacce_sva_ops = {
	.mm_exit = uacce_sva_exit,
};

static int uacce_fops_open(struct inode *inode, struct file *filep)
{
	struct iommu_sva *handle = NULL;
	struct uacce_device *uacce;
	struct uacce_queue *q;
	int ret = 0;
	int pasid = 0;

	uacce = xa_load(&uacce_xa, iminor(inode));
	if (!uacce)
		return -ENODEV;

	if (!try_module_get(uacce->parent->driver->owner))
		return -ENODEV;

	q = kzalloc(sizeof(struct uacce_queue), GFP_KERNEL);
	if (!q) {
		ret = -ENOMEM;
		goto out_with_module;
	}

	if (uacce->flags & UACCE_DEV_SVA) {
		handle = iommu_sva_bind_device(uacce->parent, current->mm, uacce);
		if (IS_ERR(handle))
			goto out_with_mem;

		ret = iommu_sva_set_ops(handle, &uacce_sva_ops);
		if (ret)
			goto out_unbind;

		pasid = iommu_sva_get_pasid(handle);
		if (pasid == IOMMU_PASID_INVALID)
			goto out_unbind;
	}

	if (uacce->ops->get_queue) {
		ret = uacce->ops->get_queue(uacce, pasid, q);
		if (ret < 0)
			goto out_unbind;
	}

	q->pid = task_pid_nr(current);
	q->pasid = pasid;
	q->handle = handle;
	q->uacce = uacce;
	q->state = UACCE_Q_INIT;
	init_waitqueue_head(&q->wait);
	filep->private_data = q;

	mutex_lock(&uacce->q_lock);
	list_add(&q->list, &uacce->qs);
	mutex_unlock(&uacce->q_lock);

	return 0;

out_unbind:
	if (uacce->flags & UACCE_DEV_SVA)
		iommu_sva_unbind_device(handle);
out_with_mem:
	kfree(q);
out_with_module:
	module_put(uacce->parent->driver->owner);
	return ret;
}

static int uacce_fops_release(struct inode *inode, struct file *filep)
{
	struct uacce_queue *q = filep->private_data;
	struct uacce_device *uacce = q->uacce;

	uacce_put_queue(q);

	if (uacce->flags & UACCE_DEV_SVA)
		iommu_sva_unbind_device(q->handle);

	mutex_lock(&uacce->q_lock);
	list_del(&q->list);
	mutex_unlock(&uacce->q_lock);
	kfree(q);
	module_put(uacce->parent->driver->owner);

	return 0;
}

static void uacce_vma_close(struct vm_area_struct *vma)
{
	struct uacce_queue *q = vma->vm_private_data;
	struct uacce_qfile_region *qfr = NULL;

	if (vma->vm_pgoff < UACCE_MAX_REGION)
		qfr = q->qfrs[vma->vm_pgoff];

	kfree(qfr);
}

static const struct vm_operations_struct uacce_vm_ops = {
	.close = uacce_vma_close,
};

static struct uacce_qfile_region *
uacce_create_region(struct uacce_queue *q, struct vm_area_struct *vma,
		    enum uacce_qfrt type, unsigned int flags)
{
	struct uacce_device *uacce = q->uacce;
	struct uacce_qfile_region *qfr;
	int ret = -ENOMEM;

	qfr = kzalloc(sizeof(*qfr), GFP_KERNEL);
	if (!qfr)
		return ERR_PTR(-ENOMEM);

	qfr->type = type;
	qfr->flags = flags;

	if (flags & UACCE_QFRF_SELFMT) {
		if (!uacce->ops->mmap) {
			ret = -EINVAL;
			goto err_with_qfr;
		}

		ret = uacce->ops->mmap(q, vma, qfr);
		if (ret)
			goto err_with_qfr;
		return qfr;
	}

	return qfr;

err_with_qfr:
	kfree(qfr);
	return ERR_PTR(ret);
}

static int uacce_fops_mmap(struct file *filep, struct vm_area_struct *vma)
{
	struct uacce_queue *q = filep->private_data;
	struct uacce_device *uacce = q->uacce;
	struct uacce_qfile_region *qfr;
	enum uacce_qfrt type = 0;
	unsigned int flags = 0;
	int ret = 0;

	if (vma->vm_pgoff < UACCE_MAX_REGION)
		type = vma->vm_pgoff;

	vma->vm_flags |= VM_DONTCOPY | VM_DONTEXPAND | VM_WIPEONFORK;
	vma->vm_ops = &uacce_vm_ops;
	vma->vm_private_data = q;

	mutex_lock(&uacce_mutex);

	if (q->qfrs[type]) {
		ret = -EEXIST;
		goto out_with_lock;
	}

	switch (type) {
	case UACCE_QFRT_MMIO:
		flags = UACCE_QFRF_SELFMT;
		break;

	case UACCE_QFRT_DUS:
		if (uacce->flags & UACCE_DEV_SVA) {
			flags = UACCE_QFRF_SELFMT;
			break;
		}
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

out_with_lock:
	mutex_unlock(&uacce_mutex);

	return ret;
}

static __poll_t uacce_fops_poll(struct file *file, poll_table *wait)
{
	struct uacce_queue *q = file->private_data;
	struct uacce_device *uacce = q->uacce;

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

#define to_uacce_device(dev) container_of(dev, struct uacce_device, dev)

static ssize_t id_show(struct device *dev,
		       struct device_attribute *attr, char *buf)
{
	struct uacce_device *uacce = to_uacce_device(dev);

	return sprintf(buf, "%d\n", uacce->dev_id);
}

static ssize_t api_show(struct device *dev,
			struct device_attribute *attr, char *buf)
{
	struct uacce_device *uacce = to_uacce_device(dev);

	return sprintf(buf, "%s\n", uacce->api_ver);
}

static ssize_t numa_distance_show(struct device *dev,
				  struct device_attribute *attr, char *buf)
{
	struct uacce_device *uacce = to_uacce_device(dev);
	int distance;

	distance = node_distance(smp_processor_id(), uacce->parent->numa_node);

	return sprintf(buf, "%d\n", abs(distance));
}

static ssize_t node_id_show(struct device *dev,
			    struct device_attribute *attr, char *buf)
{
	struct uacce_device *uacce = to_uacce_device(dev);
	int node_id;

	node_id = dev_to_node(uacce->parent);

	return sprintf(buf, "%d\n", node_id);
}

static ssize_t flags_show(struct device *dev,
			  struct device_attribute *attr, char *buf)
{
	struct uacce_device *uacce = to_uacce_device(dev);

	return sprintf(buf, "%u\n", uacce->flags);
}

static ssize_t available_instances_show(struct device *dev,
					struct device_attribute *attr,
					char *buf)
{
	struct uacce_device *uacce = to_uacce_device(dev);
	int val = 0;

	if (uacce->ops->get_available_instances)
		val = uacce->ops->get_available_instances(uacce);

	return sprintf(buf, "%d\n", val);
}

static ssize_t algorithms_show(struct device *dev,
			       struct device_attribute *attr, char *buf)
{
	struct uacce_device *uacce = to_uacce_device(dev);

	return sprintf(buf, "%s\n", uacce->algs);
}

static ssize_t region_mmio_size_show(struct device *dev,
				     struct device_attribute *attr, char *buf)
{
	struct uacce_device *uacce = to_uacce_device(dev);

	return sprintf(buf, "%lu\n",
		       uacce->qf_pg_size[UACCE_QFRT_MMIO] << PAGE_SHIFT);
}

static ssize_t region_dus_size_show(struct device *dev,
				    struct device_attribute *attr, char *buf)
{
	struct uacce_device *uacce = to_uacce_device(dev);

	return sprintf(buf, "%lu\n",
		       uacce->qf_pg_size[UACCE_QFRT_DUS] << PAGE_SHIFT);
}

static DEVICE_ATTR_RO(id);
static DEVICE_ATTR_RO(api);
static DEVICE_ATTR_RO(numa_distance);
static DEVICE_ATTR_RO(node_id);
static DEVICE_ATTR_RO(flags);
static DEVICE_ATTR_RO(available_instances);
static DEVICE_ATTR_RO(algorithms);
static DEVICE_ATTR_RO(region_mmio_size);
static DEVICE_ATTR_RO(region_dus_size);

static struct attribute *uacce_dev_attrs[] = {
	&dev_attr_id.attr,
	&dev_attr_api.attr,
	&dev_attr_numa_distance.attr,
	&dev_attr_node_id.attr,
	&dev_attr_flags.attr,
	&dev_attr_available_instances.attr,
	&dev_attr_algorithms.attr,
	&dev_attr_region_mmio_size.attr,
	&dev_attr_region_dus_size.attr,
	NULL,
};
ATTRIBUTE_GROUPS(uacce_dev);

static void uacce_release(struct device *dev)
{
	struct uacce_device *uacce = to_uacce_device(dev);

	kfree(uacce);
}

/**
 * uacce_register() - register an accelerator
 * @parent: pointer of uacce parent device
 * @interface: pointer of uacce_interface for register
 *
 * Return 0 if register succeeded, or an error.
 * Need check returned negotiated uacce->flag
 */
struct uacce_device *uacce_register(struct device *parent,
				    struct uacce_interface *interface)
{
	unsigned int flags = interface->flags;
	struct uacce_device *uacce;
	int ret;

	uacce = kzalloc(sizeof(struct uacce_device), GFP_KERNEL);
	if (!uacce)
		return ERR_PTR(-ENOMEM);

	if (flags & UACCE_DEV_SVA) {
		ret = iommu_dev_enable_feature(parent, IOMMU_DEV_FEAT_SVA);
		if (ret)
			flags &= ~UACCE_DEV_SVA;
	}

	uacce->parent = parent;
	uacce->flags = flags;
	uacce->ops = interface->ops;

	ret = xa_alloc(&uacce_xa, &uacce->dev_id, uacce, xa_limit_32b,
		       GFP_KERNEL);
	if (ret < 0)
		goto err_with_uacce;

	uacce->cdev = cdev_alloc();
	if (!uacce->cdev) {
		ret = -ENOMEM;
		goto err_with_xa;
	}

	INIT_LIST_HEAD(&uacce->qs);
	mutex_init(&uacce->q_lock);
	uacce->cdev->ops = &uacce_fops;
	uacce->cdev->owner = THIS_MODULE;
	device_initialize(&uacce->dev);
	uacce->dev.devt = MKDEV(MAJOR(uacce_devt), uacce->dev_id);
	uacce->dev.class = uacce_class;
	uacce->dev.groups = uacce_dev_groups;
	uacce->dev.parent = uacce->parent;
	uacce->dev.release = uacce_release;
	dev_set_name(&uacce->dev, "%s-%d", interface->name, uacce->dev_id);
	ret = cdev_device_add(uacce->cdev, &uacce->dev);
	if (ret)
		goto err_with_cdev;

	return uacce;

err_with_cdev:
	cdev_del(uacce->cdev);
err_with_xa:
	xa_erase(&uacce_xa, uacce->dev_id);
err_with_uacce:
	if (flags & UACCE_DEV_SVA)
		iommu_dev_disable_feature(uacce->parent, IOMMU_DEV_FEAT_SVA);
	kfree(uacce);
	return ERR_PTR(ret);
}
EXPORT_SYMBOL_GPL(uacce_register);

/**
 * uacce_unregister() - unregisters an accelerator
 * @uacce: the accelerator to unregister
 */
void uacce_unregister(struct uacce_device *uacce)
{
	if (unlikely(ZERO_OR_NULL_PTR(uacce)))
		return;

	/* ensure no open queue remains */
	mutex_lock(&uacce->q_lock);
	if (!list_empty(&uacce->qs)) {
		struct uacce_queue *q;

		list_for_each_entry(q, &uacce->qs, list) {
			uacce_put_queue(q);
			if (uacce->flags & UACCE_DEV_SVA)
				iommu_sva_unbind_device(q->handle);
		}
	}
	mutex_unlock(&uacce->q_lock);

	/* disable sva now since no opened queues */
	if (uacce->flags & UACCE_DEV_SVA)
		iommu_dev_disable_feature(uacce->parent, IOMMU_DEV_FEAT_SVA);

	cdev_device_del(uacce->cdev, &uacce->dev);
	xa_erase(&uacce_xa, uacce->dev_id);
	put_device(&uacce->dev);
}
EXPORT_SYMBOL_GPL(uacce_unregister);

static int __init uacce_init(void)
{
	int ret;

	uacce_class = class_create(THIS_MODULE, UACCE_NAME);
	if (IS_ERR(uacce_class))
		return PTR_ERR(uacce_class);

	ret = alloc_chrdev_region(&uacce_devt, 0, MINORMASK, UACCE_NAME);
	if (ret)
		class_destroy(uacce_class);

	return ret;
}

static __exit void uacce_exit(void)
{
	unregister_chrdev_region(uacce_devt, MINORMASK);
	class_destroy(uacce_class);
}

subsys_initcall(uacce_init);
module_exit(uacce_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Hisilicon Tech. Co., Ltd.");
MODULE_DESCRIPTION("Accelerator interface for Userland applications");
