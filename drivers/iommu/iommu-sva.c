// SPDX-License-Identifier: GPL-2.0
/*
 * Manage PASIDs and bind process address spaces to devices.
 *
 * Copyright (C) 2018 ARM Ltd.
 */

#include <linux/idr.h>
#include <linux/ioasid.h>
#include <linux/iommu.h>
#include <linux/sched/mm.h>
#include <linux/slab.h>
#include <linux/spinlock.h>

#include "iommu-sva.h"

/**
 * DOC: io_mm model
 *
 * The io_mm keeps track of process address spaces shared between CPU and IOMMU.
 * The following example illustrates the relation between structures
 * iommu_domain, io_mm and iommu_sva. The iommu_sva struct is a bond between
 * io_mm and device. A device can have multiple io_mm and an io_mm may be bound
 * to multiple devices.
 *              ___________________________
 *             |  IOMMU domain A           |
 *             |  ________________         |
 *             | |  IOMMU group   |        +------- io_pgtables
 *             | |                |        |
 *             | |   dev 00:00.0 ----+------- bond 1 --- io_mm X
 *             | |________________|   \    |
 *             |                       '----- bond 2 ---.
 *             |___________________________|             \
 *              ___________________________               \
 *             |  IOMMU domain B           |             io_mm Y
 *             |  ________________         |             / /
 *             | |  IOMMU group   |        |            / /
 *             | |                |        |           / /
 *             | |   dev 00:01.0 ------------ bond 3 -' /
 *             | |   dev 00:01.1 ------------ bond 4 --'
 *             | |________________|        |
 *             |                           +------- io_pgtables
 *             |___________________________|
 *
 * In this example, device 00:00.0 is in domain A, devices 00:01.* are in domain
 * B. All devices within the same domain access the same address spaces. Device
 * 00:00.0 accesses address spaces X and Y, each corresponding to an mm_struct.
 * Devices 00:01.* only access address space Y. In addition each
 * IOMMU_DOMAIN_DMA domain has a private address space, io_pgtable, that is
 * managed with iommu_map()/iommu_unmap(), and isn't shared with the CPU MMU.
 *
 * To obtain the above configuration, users would for instance issue the
 * following calls:
 *
 *     iommu_sva_bind_device(dev 00:00.0, mm X, ...) -> bond 1
 *     iommu_sva_bind_device(dev 00:00.0, mm Y, ...) -> bond 2
 *     iommu_sva_bind_device(dev 00:01.0, mm Y, ...) -> bond 3
 *     iommu_sva_bind_device(dev 00:01.1, mm Y, ...) -> bond 4
 *
 * A single Process Address Space ID (PASID) is allocated for each mm. In the
 * example, devices use PASID 1 to read/write into address space X and PASID 2
 * to read/write into address space Y. Calling iommu_sva_get_pasid() on bond 1
 * returns 1, and calling it on bonds 2-4 returns 2.
 *
 * Hardware tables describing this configuration in the IOMMU would typically
 * look like this:
 *
 *                                PASID tables
 *                                 of domain A
 *                              .->+--------+
 *                             / 0 |        |-------> io_pgtable
 *                            /    +--------+
 *            Device tables  /   1 |        |-------> pgd X
 *              +--------+  /      +--------+
 *      00:00.0 |      A |-'     2 |        |--.
 *              +--------+         +--------+   \
 *              :        :       3 |        |    \
 *              +--------+         +--------+     --> pgd Y
 *      00:01.0 |      B |--.                    /
 *              +--------+   \                  |
 *      00:01.1 |      B |----+   PASID tables  |
 *              +--------+     \   of domain B  |
 *                              '->+--------+   |
 *                               0 |        |-- | --> io_pgtable
 *                                 +--------+   |
 *                               1 |        |   |
 *                                 +--------+   |
 *                               2 |        |---'
 *                                 +--------+
 *                               3 |        |
 *                                 +--------+
 *
 * With this model, a single call binds all devices in a given domain to an
 * address space. Other devices in the domain will get the same bond implicitly.
 * However, users must issue one bind() for each device, because IOMMUs may
 * implement SVA differently. Furthermore, mandating one bind() per device
 * allows the driver to perform sanity-checks on device capabilities.
 *
 * In some IOMMUs, one entry of the PASID table (typically the first one) can
 * hold non-PASID translations. In this case PASID 0 is reserved and the first
 * entry points to the io_pgtable pointer. In other IOMMUs the io_pgtable
 * pointer is held in the device table and PASID 0 is available to the
 * allocator.
 */

struct io_mm {
	int				pasid;
	struct list_head		devices;
	struct kref			kref;
	struct mm_struct		*mm;
	const struct io_mm_ops		*ops;

	/* Private to the IOMMU driver */
	void				*ctx;
};

#define to_iommu_bond(handle) container_of(handle, struct iommu_bond, sva)

struct iommu_bond {
	struct iommu_sva		sva;
	struct io_mm			*io_mm;

	struct list_head		mm_head;
	struct list_head		dev_head;

	void				*drvdata;
	struct rcu_head			rcu_head;
	refcount_t			refs;
};

static DECLARE_IOASID_SET(shared_pasid);

/*
 * For the moment this is an all-purpose lock. It serializes
 * access/modifications to bonds and changes to io_mm refcount as well.
 *
 * Lock order: SVA lock; ioasid_lock
 */
static DEFINE_SPINLOCK(iommu_sva_lock);

/*
 * Allocate an io_mm for the given mm.
 * @mm: the mm
 * @ops: callbacks for the IOMMU driver
 * @private: private data for the IOMMU driver
 * @min_pasid: minimum PASID value (inclusive)
 * @max_pasid: maximum PASID value (inclusive)
 *
 * Returns a valid io_mm or an error pointer.
 */
static struct io_mm *io_mm_alloc(struct mm_struct *mm,
				 const struct io_mm_ops *ops, void *ctx,
				 int min_pasid, int max_pasid)
{
	int ret;
	struct io_mm *io_mm;
	struct io_mm *old = NULL;

	/*
	 * The mm must not be freed before the driver frees the io_mm (which may
	 * involve unpinning the CPU ASID for instance, requiring a valid mm
	 * struct.)
         */
	mmgrab(mm);

	io_mm = kzalloc(sizeof(*io_mm), GFP_KERNEL);
	if (!io_mm) {
		ret = -ENOMEM;
		goto out_drop_mm;
	}

	io_mm->mm		= mm;
	io_mm->ops		= ops;
	io_mm->ctx		= ctx;
	INIT_LIST_HEAD_RCU(&io_mm->devices);
	kref_init(&io_mm->kref);

	io_mm->pasid = ioasid_alloc(&shared_pasid, min_pasid, max_pasid, mm);
	if (io_mm->pasid == INVALID_IOASID) {
		ret = -ENOSPC;
		goto out_free;
	}

	spin_lock(&iommu_sva_lock);
	old = mm->iommu_context;
	if (old) {
		/*
		 * Since we put the kref and clear the iommu_context pointer in
		 * the same critical section, kref is always >0 here.
		 */
		kref_get(&old->kref);
		spin_unlock(&iommu_sva_lock);
		if (WARN_ON(old->ops != ops)) {
			old = NULL;
			ret = -EINVAL;
			goto out_release;
		}
		/* Release our io_mm and use the old one */
		ops->release(ctx);
		goto out_free_pasid;
	}

	mm->iommu_context = io_mm;
	spin_unlock(&iommu_sva_lock);

	return io_mm;

out_free_pasid:
	ioasid_free(io_mm->pasid);
out_free:
	kfree(io_mm);
out_drop_mm:
	mmdrop(mm);
	return old ?: ERR_PTR(ret);
}

static void io_mm_free(struct io_mm *io_mm)
{
	struct mm_struct *mm = io_mm->mm;

	io_mm->ops->release(io_mm->ctx);
	kfree(io_mm);
	mmdrop(mm);
}

static void io_mm_release(struct kref *kref)
{
	struct io_mm *io_mm;

	io_mm = container_of(kref, struct io_mm, kref);
	WARN_ON(!list_empty(&io_mm->devices));

	/* We're holding iommu_sva_lock, which protects this */
	io_mm->mm->iommu_context = NULL;

	ioasid_free(io_mm->pasid);

	io_mm_free(io_mm);
}

static void io_mm_put_locked(struct io_mm *io_mm)
{
	kref_put(&io_mm->kref, io_mm_release);
}

static void io_mm_put(struct io_mm *io_mm)
{
	spin_lock(&iommu_sva_lock);
	io_mm_put_locked(io_mm);
	spin_unlock(&iommu_sva_lock);
}

static struct iommu_sva *
io_mm_attach(struct device *dev, struct io_mm *io_mm, void *drvdata)
{
	int ret = 0;
	struct iommu_bond *bond, *tmp;
	struct iommu_sva_param *param = dev->iommu_param->sva_param;

	if (WARN_ON(!mutex_is_locked(&dev->iommu_param->sva_lock)))
		return ERR_PTR(-EINVAL);

	if (!param)
		return ERR_PTR(-ENODEV);

	bond = kzalloc(sizeof(*bond), GFP_KERNEL);
	if (!bond)
		return ERR_PTR(-ENOMEM);

	bond->io_mm	= io_mm;
	bond->sva.dev	= dev;
	bond->drvdata	= drvdata;
	refcount_set(&bond->refs, 1);

	spin_lock(&iommu_sva_lock);
	/* Is it already bound to the device? */
	list_for_each_entry(tmp, &io_mm->devices, mm_head) {
		if (tmp->sva.dev != dev)
			continue;

		if (WARN_ON(tmp->drvdata != drvdata)) {
			ret = -EINVAL;
			goto err_free;
		}

		/*
		 * Hold a single io_mm reference per bond. Note that we can't
		 * return an error after this, otherwise the caller would drop a
		 * reference to the wrong io_mm.
		 */
		refcount_inc(&tmp->refs);
		io_mm_put_locked(io_mm);
		kfree(bond);
		spin_unlock(&iommu_sva_lock);
		return &tmp->sva;
	}

	list_add_rcu(&bond->mm_head, &io_mm->devices);
	param->nr_mms++;
	spin_unlock(&iommu_sva_lock);

	ret = io_mm->ops->attach(bond->sva.dev, io_mm->pasid, io_mm->ctx);
	if (ret)
		goto err_remove;

	return &bond->sva;

err_remove:
	/*
	 * At this point concurrent threads may have started to access the
	 * io_mm->devices list in order to invalidate address ranges, which
	 * should be harmless.
	 */
	spin_lock(&iommu_sva_lock);
	list_del_rcu(&bond->mm_head);
	param->nr_mms--;

err_free:
	spin_unlock(&iommu_sva_lock);
	kfree(bond);
	return ERR_PTR(ret);
}

static void io_mm_detach_locked(struct iommu_bond *bond)
{
	struct io_mm *io_mm;

	io_mm = rcu_dereference_protected(bond->io_mm,
					  lockdep_is_held(&iommu_sva_lock));
	if (!io_mm)
		return;

	/* Clear the PASID entry, invalidate TLBs and drop the mm.  */
	list_del_rcu(&bond->mm_head);
	io_mm->ops->detach(bond->sva.dev, io_mm->pasid, io_mm->ctx);
	io_mm_put_locked(io_mm);
	rcu_assign_pointer(bond->io_mm, NULL);
}

static void iommu_unbind_locked(struct iommu_bond *bond)
{
	struct device *dev = bond->sva.dev;
	struct iommu_sva_param *param = dev->iommu_param->sva_param;

	if (!refcount_dec_and_test(&bond->refs))
		return;

	io_mm_detach_locked(bond);
	param->nr_mms--;
	kfree_rcu(bond, rcu_head);
}

struct iommu_sva *
iommu_sva_bind_generic(struct device *dev, struct mm_struct *mm,
		       void *ctx, const struct io_mm_ops *ops,
		       void *drvdata)
{
	struct io_mm *io_mm;
	struct iommu_sva *handle;
	struct iommu_param *param = dev->iommu_param;

	if (!param)
		return ERR_PTR(-ENODEV);

	mutex_lock(&param->sva_lock);
	if (!param->sva_param) {
		handle = ERR_PTR(-ENODEV);
		goto out_unlock;
	}

	io_mm = io_mm_alloc(mm, ops, ctx,
			    param->sva_param->min_pasid,
			    param->sva_param->max_pasid);
	if (IS_ERR(io_mm)) {
		handle = ERR_CAST(io_mm);
		goto out_unlock;
	}

	handle = io_mm_attach(dev, io_mm, drvdata);
	if (IS_ERR(handle))
		io_mm_put(io_mm);

out_unlock:
	mutex_unlock(&param->sva_lock);
	return handle;
}
EXPORT_SYMBOL_GPL(iommu_sva_bind_generic);

void iommu_sva_unbind_generic(struct iommu_sva *handle)
{
	struct iommu_param *param = handle->dev->iommu_param;

	if (WARN_ON(!param))
		return;

	mutex_lock(&param->sva_lock);
	spin_lock(&iommu_sva_lock);
	iommu_unbind_locked(to_iommu_bond(handle));
	spin_unlock(&iommu_sva_lock);
	mutex_unlock(&param->sva_lock);
}
EXPORT_SYMBOL_GPL(iommu_sva_unbind_generic);

/**
 * iommu_sva_enable() - Enable Shared Virtual Addressing for a device
 * @dev: the device
 * @sva_param
 *
 * Called by an IOMMU driver to setup the SVA parameters
 *
 * Return 0 if initialization succeeded, or an error.
 */
int iommu_sva_enable(struct device *dev, struct iommu_sva_param *sva_param)
{
	int ret;
	struct iommu_sva_param *new_param;
	struct iommu_param *param = dev->iommu_param;

	if (!param)
		return -ENODEV;

	new_param = kmemdup(sva_param, sizeof(*new_param), GFP_KERNEL);
	if (!new_param)
		return -ENOMEM;

	mutex_lock(&param->sva_lock);
	if (param->sva_param) {
		ret = -EEXIST;
		goto err_unlock;
	}

	dev->iommu_param->sva_param = new_param;
	mutex_unlock(&param->sva_lock);
	return 0;

err_unlock:
	mutex_unlock(&param->sva_lock);
	kfree(new_param);
	return ret;
}
EXPORT_SYMBOL_GPL(iommu_sva_enable);

/**
 * iommu_sva_disable() - Disable Shared Virtual Addressing for a device
 * @dev: the device
 *
 * IOMMU drivers call this to disable SVA.
 */
int iommu_sva_disable(struct device *dev)
{
	int ret = 0;
	struct iommu_param *param = dev->iommu_param;

	if (!param)
		return -EINVAL;

	mutex_lock(&param->sva_lock);
	if (!param->sva_param) {
		ret = -ENODEV;
		goto out_unlock;
	}

	/* Require that all contexts are unbound */
	if (param->sva_param->nr_mms) {
		ret = -EBUSY;
		goto out_unlock;
	}

	kfree(param->sva_param);
	param->sva_param = NULL;
out_unlock:
	mutex_unlock(&param->sva_lock);

	return ret;
}
EXPORT_SYMBOL_GPL(iommu_sva_disable);

bool iommu_sva_enabled(struct device *dev)
{
	bool enabled;
	struct iommu_param *param = dev->iommu_param;

	if (!param)
		return false;

	mutex_lock(&param->sva_lock);
	enabled = !!param->sva_param;
	mutex_unlock(&param->sva_lock);
	return enabled;
}
EXPORT_SYMBOL_GPL(iommu_sva_enabled);

int iommu_sva_get_pasid_generic(struct iommu_sva *handle)
{
	int pasid = IOMMU_PASID_INVALID;
	struct iommu_bond *bond = to_iommu_bond(handle);

	/* bond->io_mm is protected by RCU, and removed when the mm exits. */
	rcu_read_lock();
	if (bond->io_mm)
		pasid = bond->io_mm->pasid;
	rcu_read_unlock();
	return pasid;
}
EXPORT_SYMBOL_GPL(iommu_sva_get_pasid_generic);
