/* SPDX-License-Identifier: GPL-2.0-only */

#ifndef __VIRTIO_H__
#define __VIRTIO_H__

#include <stdint.h>

/* Status byte for guest to report progress, and synchronize features. */
/* We have seen device and processed generic fields (VIRTIO_CONFIG_F_VIRTIO) */
#define VIRTIO_CONFIG_S_ACKNOWLEDGE	1
/* We have found a driver for the device. */
#define VIRTIO_CONFIG_S_DRIVER		2
/* Driver has used its parts of the config, and is happy */
#define VIRTIO_CONFIG_S_DRIVER_OK	4
/* Driver has finished configuring features */
#define VIRTIO_CONFIG_S_FEATURES_OK	8
/* Device entered invalid state, driver must reset it */
#define VIRTIO_CONFIG_S_NEEDS_RESET	0x40
/* We've given up on this device. */
#define VIRTIO_CONFIG_S_FAILED		0x80

/* TODO: Save some memory and use num_queues */
#define VIRTIO_DEV_MAX_QUEUES	64

/* This marks a buffer as continuing via the next field. */
#define VIRTQ_DESC_F_NEXT	1
/* This marks a buffer as device write-only (otherwise device read-only). */
#define VIRTQ_DESC_F_WRITE	2
/* This means the buffer contains a list of buffer descriptors. */
#define VIRTQ_DESC_F_INDIRECT	4

/* We support indirect buffer descriptors */
#define VIRTIO_RING_F_INDIRECT_DESC	28

#define VIRTIO_RING_F_EVENT_IDX		29

struct virtq_desc {
	/* Address (guest-physical). */
	uint64_t addr;
	/* Length. */
	uint32_t len;
	/* The flags as indicated above. */
	uint16_t flags;
	/* Next field if flags & NEXT */
	uint16_t next;
};

struct indirect_descriptor_table {
	/* The actual descriptors (16 bytes each) */
	struct virtq_desc *desc;
};

#define VIRTQ_AVAIL_F_NO_INTERRUPT	1
struct virtq_avail {
	uint16_t flags;
	uint16_t idx;
	/*uint16_t ring[ Queue size ];*/
	/*uint16_t used_event;  Only if VIRTIO_RING_F_EVENT_IDX */
};

#define VIRTQ_USED_F_NO_NOTIFY	1
struct virtq_used_elem {
	/* Index of start of used descriptor chain. */
	uint32_t id;
	/* Total length of the descriptor chain which was used (written to) */
	uint32_t len;
};

struct virtq_used {
	uint16_t flags;
	uint16_t idx;
	/*struct virtq_used_elem ring[ Queue size ];*/
	/*uint16_t avail_event;  Only if VIRTIO_RING_F_EVENT_IDX */
};

struct virtio_queue {
	uint64_t desc_gpa;
	uint64_t avail_gpa;
	uint64_t used_gpa;
	struct virtq_desc *desc;
	struct virtq_avail *avail;
	uint16_t *avail_ring;
	uint16_t *used_event;
	struct virtq_used *used;
	struct virtq_used_elem *used_ring;
	uint16_t *avail_event;
	uint64_t queue_notify_addr;
	uint16_t queue_size;
	uint16_t aidx_old;
	uint16_t uidx_old;
};

struct virtio_queueset {
	uint64_t vq_notify_start;
	uint64_t vq_notify_end;
	struct virtio_queue vq[VIRTIO_DEV_MAX_QUEUES];
};

struct virtio_gpu_ctrl_hdr {
	uint32_t type;
	uint32_t flags;
	uint64_t fence_id;
	uint32_t ctx_id;
	uint32_t padding;
};

struct virtio_gpu_resource_attach_backing {
	struct virtio_gpu_ctrl_hdr hdr;
	uint32_t resource_id;
	uint32_t nr_entries;
};

struct virtio_gpu_mem_entry {
	uint64_t addr;
	uint32_t length;
	uint32_t padding;
};

enum virtio_gpu_ctrl_type {
	VIRTIO_GPU_UNDEFINED = 0,

	/* 2d commands */
	VIRTIO_GPU_CMD_GET_DISPLAY_INFO = 0x0100,
	VIRTIO_GPU_CMD_RESOURCE_CREATE_2D,
	VIRTIO_GPU_CMD_RESOURCE_UNREF,
	VIRTIO_GPU_CMD_SET_SCANOUT,
	VIRTIO_GPU_CMD_RESOURCE_FLUSH,
	VIRTIO_GPU_CMD_TRANSFER_TO_HOST_2D,
	VIRTIO_GPU_CMD_RESOURCE_ATTACH_BACKING,
	VIRTIO_GPU_CMD_RESOURCE_DETACH_BACKING,
};

/* These two define direction. */
#define VIRTIO_BLK_T_IN		0
#define VIRTIO_BLK_T_OUT	1

struct virtio_blk_req {
	uint32_t type;
	uint32_t reserved;
	uint64_t sector;
	uint8_t *data;
	uint8_t status;
};
#endif // __VIRTIO_H__
