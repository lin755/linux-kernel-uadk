.. SPDX-License-Identifier: GPL-2.0

Introduction of Uacce
=========================

Uacce (Unified/User-space-access-intended Accelerator Framework) targets to
provide Shared Virtual Addressing (SVA) between accelerators and processes.
So accelerator can access any data structure of the main cpu.
This differs from the data sharing between cpu and io device, which share
data content rather than address.
Because of the unified address, hardware and user space of process can
share the same virtual address in the communication.
Uacce takes the hardware accelerator as a heterogeneous processor, while
IOMMU share the same CPU page tables and as a result the same translation
from va to pa.

	 __________________________       __________________________
	|                          |     |                          |
	|  User application (CPU)  |     |   Hardware Accelerator   |
	|__________________________|     |__________________________|

	             |                                 |
	             | va                              | va
	             V                                 V
                 __________                        __________
                |          |                      |          |
                |   MMU    |                      |  IOMMU   |
                |__________|                      |__________|
		     |                                 |
	             |                                 |
	             V pa                              V pa
		 _______________________________________
		|                                       |
		|              Memory                   |
		|_______________________________________|



Architecture
------------

Uacce is the kernel module, taking charge of iommu and address sharing.
The user drivers and libraries are called WarpDrive.

A virtual concept, queue, is used for the communication. It provides a
FIFO-like interface. And it maintains a unified address space between the
application and all involved hardware.

                             ___________________                  ________________
                            |                   |   user API     |                |
                            | WarpDrive library | ------------>  |  user driver   |
                            |___________________|                |________________|
                                     |                                    |
                                     |                                    |
                                     | queue fd                           |
                                     |                                    |
                                     |                                    |
                                     v                                    |
     ___________________         _________                                |
    |                   |       |         |                               | mmap memory
    | Other framework   |       |  uacce  |                               | r/w interface
    | crypto/nic/others |       |_________|                               |
    |___________________|                                                 |
             |                       |                                    |
             | register              | register                           |
             |                       |                                    |
             |                       |                                    |
             |                _________________       __________          |
             |               |                 |     |          |         |
              -------------  |  Device Driver  |     |  IOMMU   |         |
                             |_________________|     |__________|         |
                                     |                                    |
                                     |                                    V
                                     |                            ___________________
                                     |                           |                   |
                                     --------------------------  |  Device(Hardware) |
                                                                 |___________________|


How does it work
================

Uacce uses mmap and IOMMU to play the trick.

Uacce create a chrdev for every device registered to it. New queue is
created when user application open the chrdev. The file descriptor is used
as the user handle of the queue.
The accelerator device present itself as an Uacce object, which exports as
chrdev to the user space. The user application communicates with the
hardware by ioctl (as control path) or share memory (as data path).

The control path to the hardware is via file operation, while data path is
via mmap space of the queue fd.

The queue file address space:

enum uacce_qfrt {
	UACCE_QFRT_MMIO = 0,	/* device mmio region */
	UACCE_QFRT_DKO = 1,	/* device kernel-only region */
	UACCE_QFRT_DUS = 2,	/* device user share region */
	UACCE_QFRT_SS = 3,	/* static shared memory (for non-sva devices) */
	UACCE_QFRT_MAX,
};

All regions are optional and differ from device type to type. The
communication protocol is wrapped by the user driver.

The device mmio region is mapped to the hardware mmio space. It is generally
used for doorbell or other notification to the hardware. It is not fast enough
as data channel.

The device kernel-only region is necessary only if the device IOMMU has no
PASID support or it cannot send kernel-only address request. In this case, if
kernel need to share memory with the device, kernel has to share iova address
space with the user process via mmap, to prevent iova conflict.

The device user share region is used for share data buffer between user process
and device. It can be merged into other regions. But a separated region can help
on device state management. For example, the device can be started when this
region is mapped.

The static share virtual memory region is used for share data buffer with the
device and can be shared among queues / devices.
Its size is set according to the application requirement.


The user API
------------

We adopt a polling style interface in the user space: ::

        int wd_request_queue(struct wd_queue *q);
        void wd_release_queue(struct wd_queue *q);
        int wd_send(struct wd_queue *q, void *req);
        int wd_recv(struct wd_queue *q, void **req);
        int wd_recv_sync(struct wd_queue *q, void **req);
        void wd_flush(struct wd_queue *q);

wd_recv_sync() is a wrapper to its non-sync version. It will trap into
kernel and wait until the queue become available.

If the queue do not support SVA/SVM. The following helper functions
can be used to create Static Virtual Share Memory: ::

        void *wd_reserve_memory(struct wd_queue *q, size_t size);
	int wd_share_reserved_memory(struct wd_queue *q,
				     struct wd_queue *target_q);

The user API is not mandatory. It is simply a suggestion and hint what the
kernel interface is supposed to be.


The user driver
---------------

The queue file mmap space will need a user driver to wrap the communication
protocol. Uacce provides some attributes in sysfs for the user driver to
match the right accelerator accordingly.
More details in Documentation/ABI/testing/sysfs-driver-uacce.


The Uacce register API
-----------------------
The register API is defined in uacce.h.

struct uacce_interface {
	char name[32];
	unsigned int flags;
	struct uacce_ops *ops;
};

struct uacce *uacce_register(struct device *parent,
			     struct uacce_interface *interface);
void uacce_unregister(struct uacce *uacce);
void uacce_wake_up(struct uacce_queue *q);


According to the IOMMU capability, Uacce categories the devices as below:

UACCE_DEV_SVA (UACCE_DEV_PASID | UACCE_DEV_FAULT_FROM_DEV)
        The device has IOMMU which can share the same page table with user
        process

UACCE_DEV_SHARE_DOMAIN
        This is used for device which does not support pasid.


The Memory Sharing Model
------------------------
The perfect form of a Uacce device is to support SVM/SVA. We built this upon
Jean Philippe Brucker's SVA patches. [1]

If the hardware support SVA, the user process's page table is shared to the
opened queue. So the device can access any address in the process address
space. And it can raise a page fault if the physical page is not available
yet. It can also access the address in the kernel space, which is referred by
another page table particular to the kernel. Most of IOMMU implementation can
handle this by a tag on the address request of the device. For example, ARM
SMMU uses SSV bit to indicate that the address request is for kernel or user
space.

The device_attr UACCE_DEV_SVA is used to indicate this capability of the
device. It is a combination of UACCE_DEV_FAULT_FROM_DEV and UACCE_DEV_PASID.

If the device does not support UACCE_DEV_FAULT_FROM_DEV but UACCE_DEV_PASID.
Uacce will create an unmanaged iommu_domain for the device. So it can be
bound to multiple processes. In this case, the device cannot share the user
page table directly. The user process must map the Static Share Queue File
Region to create the connection. The Uacce kernel module will allocate
physical memory to the region for both the device and the user process.

If the device does not support UACCE_DEV_PASID either. There is no way for
Uacce to support multiple process. Every Uacce allow only one process at
the same time. In this case, DMA API cannot be used in this device. If the
device driver need to share memory with the device, it should use QFRT_KO
queue file region instead. This region is mmaped from the user space but
valid only for kernel.

We suggest the driver use uacce_mode module parameter to choose the working
mode of the device. It can be:

UACCE_MODE_NOUACCE (0)
        Do not register to uacce. In this mode, the driver can register to
        other kernel framework, such as crypto

UACCE_MODE_UACCE (1)
        Register to uacce. In this mode, the driver register to uacce. It can
        register to other kernel framework according to whether it supports
        PASID.


The Folk Scenario
=================
For a process with allocated queues and shared memory, what happen if it forks
a child?

The fd of the queue will be duplicated on folk, so the child can send request
to the same queue as its parent. But the requests which is sent from processes
except for the one who opens the queue will be blocked.

It is recommended to add O_CLOEXEC to the queue file.

The queue mmap space has a VM_DONTCOPY in its VMA. So the child will lose all
those VMAs.

This is a reason why Uacce does not adopt the mode used in VFIO and
InfiniBand.  Both solutions can set any user pointer for hardware sharing.
But they cannot support fork when the dma is in process. Or the
"Copy-On-Write" procedure will make the parent process lost its physical
pages.


Difference to the VFIO and IB framework
---------------------------------------
The essential function of Uacce is to let the device access the user
address directly. There are many device drivers doing the same in the kernel.
And both VFIO and IB can provide similar function in framework level.

But Uacce has a different goal: "share address space". It is
not taken the request to the accelerator as an enclosure data structure. It
takes the accelerator as another thread of the same process. So the
accelerator can refer to any address used by the process.

Both VFIO and IB are taken this as "memory sharing", not "address sharing".
They care more on sharing the block of memory. But if there is an address
stored in the block and referring to another memory region. The address may
not be valid.

By adding more constraints to the VFIO and IB framework, in some sense, we may
achieve a similar goal. But we gave it up finally. Both VFIO and IB have extra
assumption which is unnecessary to Uacce. They may hurt each other if we
try to merge them together.

VFIO manages resource of a hardware as a "virtual device". If a device need to
serve a separated application. It must isolate the resource as separate
virtual device.  And the life cycle of the application and virtual device are
unnecessary unrelated. And most concepts, such as bus, driver, probe and
so on, to make it as a "device" is unnecessary either. And the logic added to
VFIO to make address sharing do no help on "creating a virtual device".

IB creates a "verbs" standard for sharing memory region to another remote
entity.  Most of these verbs are to make memory region between entities to be
synchronized.  This is not what accelerator need. Accelerator is in the same
memory system with the CPU. It refers to the same memory system among CPU and
devices. So the local memory terms/verbs are good enough for it. Extra "verbs"
are not necessary. And its queue (like queue pair in IB) is the communication
channel direct to the accelerator hardware. There is nothing about memory
itself.

Further, both VFIO and IB use the "pin" (get_user_page) way to lock local
memory in place.  This is flexible. But it can cause other problems. For
example, if the user process fork a child process. The COW procedure may make
the parent process lost its pages which are sharing with the device. These may
be fixed in the future. But is not going to be easy. (There is a discussion
about this on Linux Plumbers Conference 2018 [2])

So we choose to build the solution directly on top of IOMMU interface. IOMMU
is the essential way for device and process to share their page mapping from
the hardware perspective. It will be safe to create a software solution on
this assumption.  Uacce manages the IOMMU interface for the accelerator
device, so the device driver can export some of the resources to the user
space. Uacce than can make sure the device and the process have the same
address space.


References
==========
.. [1] http://jpbrucker.net/sva/
.. [2] https://lwn.net/Articles/774411/
