/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __LINUX_IOASID_H
#define __LINUX_IOASID_H

#define INVALID_IOASID ((ioasid_t)-1)
typedef unsigned int ioasid_t;
typedef int (*ioasid_iter_t)(ioasid_t ioasid, void *private, void *data);

struct ioasid_set {
	int dummy;
};

#define DECLARE_IOASID_SET(name) struct ioasid_set name = { 0 }

#ifdef CONFIG_IOASID
ioasid_t ioasid_alloc(struct ioasid_set *set, ioasid_t min, ioasid_t max,
		      void *private);
void ioasid_free(ioasid_t ioasid);

void *ioasid_find(struct ioasid_set *set, ioasid_t ioasid,
		  bool (*getter)(void *));

#else /* !CONFIG_IOASID */
static inline ioasid_t ioasid_alloc(struct ioasid_set *set, ioasid_t min,
				    ioasid_t max, void *private)
{
	return INVALID_IOASID;
}

static inline void ioasid_free(ioasid_t ioasid)
{
}

static inline void *ioasid_find(struct ioasid_set *set, ioasid_t ioasid,
				bool (*getter)(void *))
{
	return NULL;
}
#endif /* CONFIG_IOASID */
#endif /* __LINUX_IOASID_H */
