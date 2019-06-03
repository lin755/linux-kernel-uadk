// SPDX-License-Identifier: GPL-2.0
/*
 * I/O Address Space ID allocator. There is one global IOASID space, split into
 * subsets. Users create a subset with DECLARE_IOASID_SET, then allocate and
 * free IOASIDs with ioasid_alloc and ioasid_free.
 */
#include <linux/idr.h>
#include <linux/ioasid.h>
#include <linux/slab.h>
#include <linux/spinlock.h>

struct ioasid_data {
	ioasid_t id;
	struct ioasid_set *set;
	void *private;
	struct rcu_head rcu;
};

static DEFINE_IDR(ioasid_idr);

/**
 * ioasid_alloc - Allocate an IOASID
 * @set: the IOASID set
 * @min: the minimum ID (inclusive)
 * @max: the maximum ID (exclusive)
 * @private: data private to the caller
 *
 * Allocate an ID between @min and @max (or %0 and %INT_MAX). Return the
 * allocated ID on success, or INVALID_IOASID on failure. The @private pointer
 * is stored internally and can be retrieved with ioasid_find().
 */
ioasid_t ioasid_alloc(struct ioasid_set *set, ioasid_t min, ioasid_t max,
		      void *private)
{
	int id = -1;
	struct ioasid_data *data;

	data = kzalloc(sizeof(*data), GFP_KERNEL);
	if (!data)
		return INVALID_IOASID;

	data->set = set;
	data->private = private;

	idr_preload(GFP_KERNEL);
	idr_lock(&ioasid_idr);
	data->id = id = idr_alloc(&ioasid_idr, data, min, max, GFP_ATOMIC);
	idr_unlock(&ioasid_idr);
	idr_preload_end();

	if (id < 0) {
		kfree(data);
		return INVALID_IOASID;
	}
	return id;
}
EXPORT_SYMBOL_GPL(ioasid_alloc);

/**
 * ioasid_free - Free an IOASID
 * @ioasid: the ID to remove
 */
void ioasid_free(ioasid_t ioasid)
{
	struct ioasid_data *ioasid_data;

	idr_lock(&ioasid_idr);
	ioasid_data = idr_remove(&ioasid_idr, ioasid);
	idr_unlock(&ioasid_idr);

	if (ioasid_data)
		kfree_rcu(ioasid_data, rcu);
}
EXPORT_SYMBOL_GPL(ioasid_free);

/**
 * ioasid_find - Find IOASID data
 * @set: the IOASID set
 * @ioasid: the IOASID to find
 * @getter: function to call on the found object
 *
 * The optional getter function allows to take a reference to the found object
 * under the rcu lock. The function can also check if the object is still valid:
 * if @getter returns false, then the object is invalid and NULL is returned.
 *
 * If the IOASID has been allocated for this set, return the private pointer
 * passed to ioasid_alloc. Otherwise return NULL.
 */
void *ioasid_find(struct ioasid_set *set, ioasid_t ioasid,
		  bool (*getter)(void *))
{
	void *priv = NULL;
	struct ioasid_data *ioasid_data;

	rcu_read_lock();
	ioasid_data = idr_find(&ioasid_idr, ioasid);
	if (ioasid_data && ioasid_data->set == set) {
		priv = ioasid_data->private;
		if (getter && !getter(priv))
			priv = NULL;
	}
	rcu_read_unlock();

	return priv;
}
EXPORT_SYMBOL_GPL(ioasid_find);
