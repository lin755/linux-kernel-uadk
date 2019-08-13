/* SPDX-License-Identifier: GPL-2.0+ */
#ifndef HISI_QM_USR_IF_H
#define HISI_QM_USR_IF_H

struct hisi_qp_ctx {
	__u16 id;
	__u16 qc_type;
};

#define HISI_QM_API_VER_BASE "hisi_qm_v1"
#define HISI_QM_API_VER2_BASE "hisi_qm_v2"

#define UACCE_CMD_QM_SET_QP_CTX	_IOWR('H', 10, struct hisi_qp_ctx)

#endif
