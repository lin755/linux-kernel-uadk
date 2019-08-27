/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef _UAPIUUACCE_H
#define _UAPIUUACCE_H

#include <linux/types.h>
#include <linux/ioctl.h>

#define UACCE_CMD_SHARE_SVAS	_IO('W', 0)
#define UACCE_CMD_START		_IO('W', 1)

/**
 * UACCE Device Attributes:
 *
 * SHARE_DOMAIN: no PASID, can shae sva only for one process and the kernel
 * PASID: the device has IOMMU which support PASID setting
 *	  can do share sva, mapped to dev per process
 * FAULT_FROM_DEV: the device has IOMMU which can do page fault request
 *		   no need for share sva, should be used with PASID
 * SVA: full function device
 */

enum {
	UACCE_DEV_SHARE_DOMAIN = 0x0,
	UACCE_DEV_PASID = 0x1,
	UACCE_DEV_FAULT_FROM_DEV = 0x2,
	UACCE_DEV_SVA = UACCE_DEV_PASID | UACCE_DEV_FAULT_FROM_DEV,
};

#define UACCE_QFR_NA ((unsigned long)-1)

enum uacce_qfrt {
	UACCE_QFRT_MMIO = 0,	/* device mmio region */
	UACCE_QFRT_DKO = 1,	/* device kernel-only */
	UACCE_QFRT_DUS = 2,	/* device user share */
	UACCE_QFRT_SS = 3,	/* static share memory */
	UACCE_QFRT_MAX,
};

#endif
