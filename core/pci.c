// SPDX-License-Identifier: GPL-2.0-only

#include "sys_context.h"
#include "guest.h"
#include "pci.h"
#include "virtio_ids.h"
#include "virtio_config.h"
#include "hyplogs.h"
#include "armtrans.h"
#include "hvccall.h"
#include "spinlock.h"
#include "helpers.h"

#define VIRTIO_PCI_DEVISIZE 0x3FFF
/* TODO : Get all this from device tree */
#define VIRTIO_BLK_PCI_OFFT 0x8000000000
static const char virtio_pci_blk_name[] = "virtio-blk-pci";
static const char virtio_pci_input_name[] = "virtio-input-pci";
static const char virtio_pci_gpu_name[] = "virtio-gpu-pci";
static const char virtio_pci_serial_name[] = "virtio-serial-pci";
static const char virtio_pci_net_name[] = "virtio-net-pci";
static const char virtio_pci_rng_name[] = "virtio-rng-pci";
static const char virtio_pci_balloon_name[] = "virtio-balloon-pci";

static void virtio_scan_desc_chain(struct kvm_guest *guest,
			    struct virtio_pci_device *dev,
			    struct virtq_desc *desc,
			    uint16_t next, uint16_t idx_max, bool direct,
			    uint16_t qi);

int virtio_pci_device_set_status(struct virtio_pci_device *dev,
				 uint16_t status, uint8_t wnr)
{
	if (wnr && (dev->common_cfg.device_status & VIRTIO_CONFIG_S_DRIVER_OK))
		panic("Frontend not ok");

	dev->common_cfg.device_status = status;

#if 0
	uint64_t uaddr, paddr;
	/*
	 * Locate the device common space.
	 */
	uaddr = gpa_to_uaddr(guest, dev->bar);

	if (uaddr != ~0UL) {
		/*
		 * Walk the virtio pci device common configuration page
		 * physical address from the owning virtio backend page table.
		 * IPA is enough since we have 1:1 mapping at host side.
		 */
		paddr = pt_walk(guest, STAGE1, uaddr, NULL);
		if (paddr != 0UL)
			dev->common_cfg = (struct virtio_pci_common_cfg *)paddr;
		else
			return -ENOENT;
	}
#endif
	return 0;
}

struct virtio_pci_device *virtio_pci_device_get(void *g,
						uint64_t ipa,
						bool *common_access)
{
	int i;
	uint64_t bars, bare;
	struct kvm_guest *guest = (struct kvm_guest *)g;
	/*
	 * Does the IPA match one of the devices
	 * we have gathered pci configuration space.
	 */
	*common_access = false;
	for (i = 0; i < MAX_VIRTIO_PCI_DEVS; i++) {
		if (!guest->virtio_pci_dev[i].id)
			continue;
		bars = guest->virtio_pci_dev[i].bar[4].start;
		if (!bars)
			continue;
		bare = bars + guest->virtio_pci_dev[i].bar[4].size;
		if ((ipa >= bars) &&
		    (ipa < bare)) {

			if (ipa == bars)
				*common_access = true;

			return &guest->virtio_pci_dev[i];
		}
	}
	return NULL;
}

#define ALIGN_UP(x, align_to)	(((x) + ((align_to)-1)) & ~((align_to)-1))
#define ALIGN_DOWN(x, align_to) ((x) & ~((align_to)-1))

int virtio_share_guest_memory(struct kvm_guest *guest, uint64_t gpa,
			      size_t len, bool contiguous)
{
	int res;
	uint64_t _gpa;
	size_t _len;

	_gpa = ALIGN_DOWN(gpa, PAGE_SIZE);
	_len = ALIGN_UP(len, PAGE_SIZE) + PAGE_SIZE;

	/*
	 * Is the page shared already? This is the case where guest is
	 * reusing the buffer allocated for virtio queues.
	 */
	res = is_share(guest, _gpa, _len);

	if (!res)
		res = share_guest_memory(guest, _gpa, _len, contiguous);
	else
		/* Already shared - good to go */
		res = 0;

	return res;
}

void virtio_scan_gpu_ctrl(struct kvm_guest *guest, struct virtio_pci_device *dev,
			     struct virtq_desc *desc, uint64_t gpa, uint16_t *next,
			     uint16_t qi)
{
	int i;
	uint64_t hpa;
	size_t len;
	struct virtio_gpu_resource_attach_backing *gpu_resource;
	struct virtio_gpu_mem_entry *entry;

	if (qi != 0)
		return;

	hpa = pt_walk(guest, STAGE2, gpa, NULL);
	if (hpa == ~0UL) {
		ERROR("invalid gpu control 0x%llx\n", gpa);
		return;
	}

	gpu_resource = (struct virtio_gpu_resource_attach_backing *)hpa;
	if (gpu_resource->hdr.type != VIRTIO_GPU_CMD_RESOURCE_ATTACH_BACKING)
		return;

	if (!(desc[*next].flags & VIRTQ_DESC_F_NEXT) ||
	    (!desc[*next].next)) {
		ERROR("missing gpu entries!\n");
		return;
	}

	*next = desc[*next].next;
	gpa = desc[*next].addr;
	len = desc[*next].len;

	virtio_share_guest_memory(guest, gpa, len, false);

	hpa = pt_walk(guest, STAGE2, gpa, NULL);
	if (hpa == ~0UL) {
		ERROR("hpa missing for gpu memory 0x%llx\n", gpa);
		return;
	}

	entry = (struct virtio_gpu_mem_entry *)hpa;

	for (i = 0; i < gpu_resource->nr_entries; i++)
		virtio_share_guest_memory(guest, entry[i].addr, entry[i].length, false);
}

void virtio_scan_block_req(struct kvm_guest *guest, struct virtio_pci_device *dev,
			     struct virtq_desc *desc, uint64_t gpa, uint16_t *next,
			     uint16_t qi)
{
	uint64_t hpa;
	struct virtio_blk_req *blk_req;

	if (qi != 0)
		return;

	if (*next)
		return;

	hpa = pt_walk(guest, STAGE2, gpa, NULL);
	if (hpa == ~0UL) {
		ERROR("invalid block request0x%llx\n", gpa);
		return;
	}

	blk_req = (struct virtio_blk_req *)hpa;

	switch (blk_req->type) {
	case VIRTIO_BLK_T_IN:
	case VIRTIO_BLK_T_OUT:
		break;
	default:
		return;
	}

	LOG("block req (%d) addr: 0x%llx len: 0x%llx\n", blk_req->type, (uint64_t)blk_req->data, desc[*next].len);

}


void virtio_scan_device_ctrl(struct kvm_guest *guest, struct virtio_pci_device *dev,
			     struct virtq_desc *desc, uint64_t gpa, uint16_t *next,
			     uint16_t qi)
{
	switch (dev->id) {
	case PCI_DEVICE_NON_TRANSITIONAL(VIRTIO_ID_GPU):
		virtio_scan_gpu_ctrl(guest, dev, desc, gpa, next, qi);
		break;
	case VIRTIO_TRANS_ID_BLOCK:
		/*virtio_scan_block_req(guest, dev, desc, gpa, next, qi);*/
		break;
	default:
		break;
	}
}

void virtio_scan_indirect_desc_chain(struct kvm_guest *guest,
				     struct virtio_pci_device *dev,
				     uint64_t indirect_chain_ipa,
				     uint32_t indirect_chain_bytes,
				     uint16_t qi)
{
	uint16_t idx_max;
	uint64_t hpa;

	hpa = pt_walk(guest, STAGE2, indirect_chain_ipa, NULL);

	if (hpa == ~0UL) {
		ERROR("invalid deschead gpa 0x%llx\n", indirect_chain_ipa);
		return;
	}

	idx_max = (indirect_chain_bytes / sizeof(struct virtq_desc)) - 1;

	virtio_scan_desc_chain(guest, dev, (struct virtq_desc *)hpa, 0, idx_max,
			       false, qi);
}

void virtio_scan_desc_chain(struct kvm_guest *guest,
			    struct virtio_pci_device *dev,
			    struct virtq_desc *desc,
			    uint16_t next, uint16_t idx_max, bool direct,
			    uint16_t qi)
{
	uint64_t gpa;
	size_t len;
	size_t descr_idx = 0;

	do {
		/*
		 * The device MUST handle the case of zero or more normal
		 * chained descriptors followed by a single descriptor
		 * with flags&VIRTQ_DESC_F_INDIRECT.
		 */
		gpa = desc[next].addr;
		len = desc[next].len;
		if (desc[next].flags & VIRTQ_DESC_F_INDIRECT) {

			if (!direct)
				panic("nested indirect 0x%llx\n", desc);

			if (desc[next].flags & VIRTQ_DESC_F_NEXT)
				panic("invalid indirect 0x%llx\n", desc);

			/* Share the indirect descriptor list itself */
			virtio_share_guest_memory(guest, gpa, len, false);
			virtio_scan_indirect_desc_chain(guest, dev, gpa, len, qi);
			next = 0;
		} else {
			virtio_share_guest_memory(guest, gpa, len, false);
			descr_idx++;

			/* Device specific functionality */
			virtio_scan_device_ctrl(guest, dev, desc, gpa, &next, qi);

			if ((desc[next].flags & VIRTQ_DESC_F_NEXT) &&
			    (desc[next].next))
				next = desc[next].next;
			else
				next = 0;
		}

			/*
		if (descr_idx >= idx_max) {
			if (next)
				ERROR("max idx reached with next %d\n", next);

			break;
		}
			*/
	} while (next);
}

#define VQ_USED_CPY_MAX 256
bool virtio_filter_used(uint32_t *used, uint16_t idx)
{
	int i;

	for (i = 0; i < VQ_USED_CPY_MAX; i++) {
		if (used[i] == 0xFFFFFFFF)
			return false;
		if (used[i] == idx) {
			used[i] = 0x10001;
			return true;
		}
	}

	return false;
}

void virtio_scan_avail_ring(struct kvm_guest *guest,
			    struct virtio_pci_device *dev,
			    uint16_t qi)
{
	uint16_t aidxo, uidxo;
	int i;
	uint32_t used[VQ_USED_CPY_MAX];
	struct virtio_queue *vq = &dev->vqs.vq[qi];

	memset(used, 0xFF, VQ_USED_CPY_MAX * sizeof(uint32_t));

	dsbish();
	isb();


	/*
	 * We cant go and process used chains since guest may have
	 * modified the content. We are interested in chains marked
	 * as used after available index was last updated.
	 */
	i = 0;
	vq->uidx_old = vq->aidx_old;
	while (vq->uidx_old < vq->used->idx) {
		uidxo = vq->uidx_old % vq->queue_size;
		used[i++] = vq->used_ring[uidxo].id;
		if (i >= VQ_USED_CPY_MAX)
			panic("out of used slots\n");

		vq->uidx_old++;
	}

	/*
	 * idx field indicates where the driver would put the next descriptor
	 * head in the ring (modulo the queue size). Ring index starts at 0,
	 * and increases until it reaches queue size where it gets value 0
	 * again.
	 */
	if (vq->aidx_old > vq->avail->idx)
		ERROR("avail max reached!!\n");
	while (vq->aidx_old < vq->avail->idx) {
		aidxo = vq->aidx_old % vq->queue_size;
		if (!virtio_filter_used(used, vq->avail_ring[aidxo]))
			virtio_scan_desc_chain(guest, dev, vq->desc,
					       vq->avail_ring[aidxo],
					      (vq->queue_size - 1), true, qi);
		vq->aidx_old++;
	}
}


void virtio_pci_do_notify(struct kvm_guest *guest,
			  struct virtio_pci_device *dev,
			  uint16_t qi)
{
	lock_guest(guest);
	load_host_s2();

	/* Track the avail ring idx to catch the added descriptors */
	if (dev->vqs.vq[qi].avail->idx != dev->vqs.vq[qi].aidx_old)
		virtio_scan_avail_ring(guest, dev, qi);

	load_guest_s2(guest->vmid);
	unlock_guest(guest);
}

void virtio_scan_avail_rings(void *g)
{
	int di, qi;
	struct virtio_pci_device *dev;
	struct kvm_guest *guest = (struct kvm_guest *)g;
	/*
	 * Go through queues to see if there is something added after
	 * latest queue notify we have processed. This is needed in
	 * a case where frontend (guest driver) and backend (VMM device)
	 * are working in asynchronous manner using the queue idx values
	 * without notifications.
	 */
	for (di = 0; di < MAX_VIRTIO_PCI_DEVS; di++) {
		if (!guest->virtio_pci_dev[di].name)
			continue;

		dev = &guest->virtio_pci_dev[di];
		for (qi = 0; qi < dev->common_cfg.num_queues; qi++) {
			if (!dev->vqs.vq[qi].avail)
				continue;
			if (dev->vqs.vq[qi].avail->idx != dev->vqs.vq[qi].aidx_old)
				virtio_scan_avail_ring(guest, dev, qi);
		}
	}
}

struct virtio_pci_cap *virtio_pci_get_capability(struct virtio_pci_device *dev,
						 uint8_t cfg_type)
{
	int i;
	struct virtio_pci_cap *cap = NULL;

	for (i = 0; i < PCIE_MAX_CAP; i++) {
		if (!dev->cap_cfg[i].cap.cap_next)
			break;
		if (cfg_type != dev->cap_cfg[i].cap.cfg_type)
			continue;
		cap = &dev->cap_cfg[i].cap;
		break;
	}

	return cap;
}

void virtio_pci_notify_check(void *g, void *c)
{
	/*int i;*/
	struct virtio_common_io *vcio;
	struct vcpu_context *ctxt = (struct vcpu_context *)c;
	struct kvm_guest *guest = (struct kvm_guest *)g;
	struct virtio_pci_cap *cap;

	vcio = &ctxt->vcio;

	cap = virtio_pci_get_capability(vcio->dev, VIRTIO_PCI_CAP_NOTIFY_CFG);

	if (cap == NULL)
		panic("No capability");

	if ((vcio->addr < vcio->dev->vqs.vq_notify_start) ||
	    (vcio->addr > vcio->dev->vqs.vq_notify_end))
		return;

	lock_guest(guest);
	load_host_s2();

	virtio_scan_avail_rings(guest);

	load_guest_s2(guest->vmid);
	unlock_guest(guest);

	/*
	if ((vcio->addr < vcio->dev->vqs.vq_notify_start) ||
	    (vcio->addr > vcio->dev->vqs.vq_notify_end))
		return;

	for (i = 0; i < vcio->dev->common_cfg.num_queues; i++) {
		if (vcio->addr == vcio->dev->vqs.vq[i].queue_notify_addr) {
			virtio_pci_do_notify(guest, vcio->dev, i);
			break;
		}
	}
	*/

}

void virtio_pci_access(void *c)
{
	uint64_t value;
	struct virtio_common_io *vcio;
	struct vcpu_context *ctxt = (struct vcpu_context *)c;

	vcio = &ctxt->vcio;
	value = ctxt->regs.regs[vcio->reg];

	LOG("    0x%llx (%d): 0x%llx\n", vcio->addr, vcio->wnr,  value);
}

void virtio_pci_vqs_set_notify(struct virtio_pci_device *dev,
			       uint16_t notify_idx)
{
	struct virtio_pci_cap *cap;
	uint64_t notify_addr = 0;

	cap = virtio_pci_get_capability(dev, VIRTIO_PCI_CAP_NOTIFY_CFG);

	if (cap == NULL)
		panic("No capability");

	notify_addr = dev->bar[4].start + cap->offset +
		      (dev->notify_off_multiplier * notify_idx);

	dev->vqs.vq[dev->common_cfg.queue_select].queue_notify_addr =
		notify_addr;

	if (!dev->vqs.vq_notify_start || dev->vqs.vq_notify_start > notify_addr)
		dev->vqs.vq_notify_start = notify_addr;

	if (dev->vqs.vq_notify_end < notify_addr)
		dev->vqs.vq_notify_end = notify_addr;
}

void virtio_pci_vq_enable(struct kvm_guest *guest, struct virtio_queue *vq,
			  bool enable)
{
	uint64_t hpa;
	size_t size;

	if (!enable)
		return;

	lock_guest(guest);
	load_host_s2();

	hpa = pt_walk(guest, STAGE2, vq->desc_gpa, NULL);
	if (hpa != ~0UL) {
		size = vq->queue_size * 16;
		if (virtio_share_guest_memory(guest, vq->desc_gpa, size, false))
			ERROR("share vq desc 0x%llx len: %d\n", vq->desc_gpa, size);
		vq->desc = (struct virtq_desc *)hpa;
	}

	hpa = pt_walk(guest, STAGE2, vq->avail_gpa, NULL);
	if (hpa != ~0UL) {
		size = 6 + (vq->queue_size * 2);
		if (virtio_share_guest_memory(guest, vq->avail_gpa, size, false))
			ERROR("share vq avail ring 0x%llx len: %d\n", vq->desc_gpa, size);
		vq->avail = (struct virtq_avail *)hpa;
		vq->avail_ring = (uint16_t *)((uint8_t *)hpa + 4);
		vq->used_event = (uint16_t *)((uint8_t *)hpa + (4 + (vq->queue_size * 2)));
	}

	hpa = pt_walk(guest, STAGE2, vq->used_gpa, NULL);
	if (hpa != ~0UL) {
		size = 6 + (vq->queue_size * 8);
		if (virtio_share_guest_memory(guest, vq->used_gpa, size, false))
			ERROR("share vq used ring 0x%llx len: %d\n", vq->desc_gpa, size);
		vq->used = (struct virtq_used *)hpa;
		vq->used_ring = (struct virtq_used_elem *)((uint8_t *)hpa + 4);
		vq->avail_event = (uint16_t *)((uint8_t *)hpa + (4 + (vq->queue_size * 8)));
	}

	load_guest_s2(guest->vmid);
	unlock_guest(guest);

}

static void modify32_to_64(uint64_t *addr, uint32_t value, bool lo)
{
	uint64_t shift, mask;

	if (lo) {
		mask = 0xFFFFFFFF00000000UL;
		shift = 0;
	} else {
		mask = 0xFFFFFFFFUL;
		shift = 32;
	}

	*addr &= mask;
	*addr |= ((uint64_t)value << shift);
}

void virtio_pci_scan(void *g, void *c)
{
	uint64_t offt;
	uint32_t value;
	struct virtio_common_io *vcio;
	struct virtio_pci_device *dev;
	struct virtio_pci_common_cfg *cfg;
	struct vcpu_context *ctxt = (struct vcpu_context *)c;
	struct kvm_guest *guest = (struct kvm_guest *)g;

	vcio = &ctxt->vcio;
	dev = vcio->dev;
	cfg = &dev->common_cfg;
	value = (uint32_t)ctxt->regs.regs[vcio->reg];

	offt = (vcio->addr & ~PAGE_MASK);

	if (offt > VIRTIO_PCI_COMMON_Q_USEDHI)
		return;

	switch (offt) {
	/* Actions for the whole device. */
	case VIRTIO_PCI_COMMON_DFSELECT:
		/*LOG("vdev: %s device feature select(%d): 0x%llx\n", dev->name,
		    vcio->wnr,  value);*/
		cfg->device_feature_select = value;
		break;
	case VIRTIO_PCI_COMMON_DF:
		/*LOG("vdev: %s device feature(%d): sel: %d val: 0x%llx\n", dev->name,
		    vcio->wnr, cfg->device_feature_select, value);*/
		/*
		if (!cfg->device_feature_select && (value & (1 << VIRTIO_RING_F_EVENT_IDX))) {
			value &= ~(1 << VIRTIO_RING_F_EVENT_IDX);
			ctxt->regs.regs[vcio->reg] = value;
			LOG("event idx enabled -> disable: 0x%llx\n", value);
		}


		if (!cfg->device_feature_select && (value & (1 << VIRTIO_RING_F_INDIRECT_DESC))) {
			value &= ~(1 << VIRTIO_RING_F_INDIRECT_DESC);
			ctxt->regs.regs[vcio->reg] = value;
			LOG("indirect enabled -> disable: 0x%llx\n", value);
		}
		*/

		if ((cfg->device_feature_select == 1) && (value & (1 << (VIRTIO_F_RING_PACKED - 32)))) {
			LOG("packed enabled: 0x%llx\n", (1 << (VIRTIO_F_RING_PACKED - 32)));
		}

		if ((cfg->device_feature_select == 1) && (value & (1 << (VIRTIO_F_VERSION_1 - 32)))) {
			LOG("v1 enabled: 0x%llx\n", (1 << (VIRTIO_F_VERSION_1 - 32)));
		}

		cfg->device_feature = value;
		break;
	case VIRTIO_PCI_COMMON_GFSELECT:
		/*LOG("vdev: %s guest feature select(%d): 0x%llx\n", dev->name,
		    vcio->wnr,  value);*/
		cfg->guest_feature_select = value;
		break;
	case VIRTIO_PCI_COMMON_GF:
		/*LOG("vdev: %s guest feature(%d): sel: %d val: 0x%llx\n", dev->name,
		    vcio->wnr, cfg->guest_feature_select,  value);*/
		/*
		if (!cfg->guest_feature_select && (value & (1 << VIRTIO_RING_F_EVENT_IDX))) {
			value &= ~(1 << VIRTIO_RING_F_EVENT_IDX);
			ctxt->regs.regs[vcio->reg] = value;
			LOG("event idx enabled -> disable: 0x%llx\n", value);
		}
		*/
		if ((cfg->device_feature_select == 1) && (value & (1 << (VIRTIO_F_VERSION_1 - 32)))) {
			LOG("v1 enabled: 0x%llx\n", (1 << (VIRTIO_F_VERSION_1 - 32)));
		}
		break;
	case VIRTIO_PCI_COMMON_MSIX:
		/*LOG("vdev: %s msix config(%d): 0x%llx\n", dev->name, vcio->wnr,
		    value);*/
		cfg->msix_config = value;
		break;
	case VIRTIO_PCI_COMMON_NUMQ:
		/*LOG("vdev: %s num queues(%d): %d\n", dev->name, vcio->wnr,  value);*/
		cfg->num_queues = value;

		if (value > VIRTIO_DEV_MAX_QUEUES)
			panic("vdev: %s too many queues(%d): %d\n", dev->name,
			      vcio->wnr,  value);
		break;
	case VIRTIO_PCI_COMMON_STATUS:
		/*
		 * Virtio device is reset by writing zero value to
		 * configuration register.
		 */
		/*LOG("vdev: %s device status(%d): 0x%llx\n", dev->name,
		    vcio->wnr, value);*/
		virtio_pci_device_set_status(dev, value, vcio->wnr);
	case VIRTIO_PCI_COMMON_CFGGENERATION:
		break;
	/* From this on the action is for a specific virtqueue. */
	case VIRTIO_PCI_COMMON_Q_SELECT:
		/*LOG("vdev: %s select queue(%d): %d\n", dev->name, vcio->wnr,
		    value);*/
		cfg->queue_select = value;
		break;
	case VIRTIO_PCI_COMMON_Q_SIZE:
		/*LOG("vdev: %s queue %d size(%d): %d\n",
		    dev->name,  cfg->queue_select, vcio->wnr, value);*/
		dev->vqs.vq[cfg->queue_select].queue_size = value;
		break;
	case VIRTIO_PCI_COMMON_Q_MSIX:
		/*LOG("vdev: %s queue %d msix vector(%d): 0x%llx\n",
		    dev->name,  cfg->queue_select, vcio->wnr, value);*/
		break;
	case VIRTIO_PCI_COMMON_Q_ENABLE:
		/*LOG("vdev: %s queue %d queue enable(%d): 0x%llx\n",
		    dev->name,  cfg->queue_select, vcio->wnr, value);*/
		if (!vcio->wnr)
			break;
		virtio_pci_vq_enable(guest, &dev->vqs.vq[cfg->queue_select],
				     !!value);
		break;
	case VIRTIO_PCI_COMMON_Q_NOFF:
		/*LOG("vdev: %s queue %d notify offset(%d): 0x%llx\n",
		    vcio->dev->name,  vcio->dev->common_cfg.queue_select, vcio->wnr,
		    value);*/
		/*
		 * Virtio queue is notified through this offset. Let's save
		 * it for this queue.
		 */
		/*cfg->queue_notify_off = value;*/
		if (!vcio->wnr)
			virtio_pci_vqs_set_notify(dev, value);
		break;
	case VIRTIO_PCI_COMMON_Q_DESCLO:
		/*cfg->queue_desc_lo = value;*/
		/*LOG("vdev: %s queue %d desclo(%d): 0x%llx\n",
		    dev->name,  cfg->queue_select, vcio->wnr, value);*/
		if (!vcio->wnr)
			break;
		modify32_to_64(&dev->vqs.vq[cfg->queue_select].desc_gpa,
			       value, true);
		break;
	case VIRTIO_PCI_COMMON_Q_DESCHI:
		/*cfg->queue_desc_hi = value;*/
		/*LOG("vdev: %s queue %d deschi(%d): 0x%llx\n",
		    dev->name,  cfg->queue_select, vcio->wnr, value);*/
		if (!vcio->wnr)
			break;
		modify32_to_64(&dev->vqs.vq[cfg->queue_select].desc_gpa,
			       value, false);
		break;
	case VIRTIO_PCI_COMMON_Q_AVAILLO:
		/*cfg->queue_avail_lo = value;*/
		/*LOG("vdev: %s queue %d availlo(%d): 0x%llx\n",
		    dev->name,  cfg->queue_select, vcio->wnr, value);*/
		if (!vcio->wnr)
			break;
		modify32_to_64(&dev->vqs.vq[cfg->queue_select].avail_gpa,
			       value, true);
		break;
	case VIRTIO_PCI_COMMON_Q_AVAILHI:
		/*cfg->queue_avail_hi = value;*/
		/*LOG("vdev: %s queue %d availhi(%d): 0x%llx\n",
		    dev->name,  cfg->queue_select, vcio->wnr, value);*/
		if (!vcio->wnr)
			break;
		modify32_to_64(&dev->vqs.vq[cfg->queue_select].avail_gpa,
			       value, false);
		break;
	case VIRTIO_PCI_COMMON_Q_USEDLO:
		/*cfg->queue_used_lo = value;*/
		/*LOG("vdev: %s queue %d usedlo(%d): 0x%llx\n",
		    dev->name,  cfg->queue_select, vcio->wnr, value);*/
		if (!vcio->wnr)
			break;
		modify32_to_64(&dev->vqs.vq[cfg->queue_select].used_gpa,
			       value, true);
		break;
	case VIRTIO_PCI_COMMON_Q_USEDHI:
		/* cfg->queue_used_hi = value; */
		/*LOG("vdev: %s queue %d usedhi(%d): 0x%llx\n",
		    dev->name,  cfg->queue_select, vcio->wnr, value);*/
		if (!vcio->wnr)
			break;
		modify32_to_64(&dev->vqs.vq[cfg->queue_select].used_gpa,
			       value, false);
		break;
	default:
		break;
	}
}

struct virtio_pci_device *virtio_pci_ecam_get_device(struct kvm_guest *guest,
						     uint32_t dev_id)
{
	int i;

	for (i = 0; i < MAX_VIRTIO_PCI_DEVS; i++) {
		if (dev_id != guest->virtio_pci_dev[i].id)
			continue;

		return &guest->virtio_pci_dev[i];
	}
	return NULL;
}

int virtio_pci_ecam_set_device(struct virtio_pci_device *dev, uint32_t dev_id)
{
	switch (dev_id) {
	case VIRTIO_TRANS_ID_NET:
		dev->name = virtio_pci_net_name;
		break;
	case VIRTIO_TRANS_ID_BLOCK:
		dev->name = virtio_pci_blk_name;
		break;
	case VIRTIO_TRANS_ID_BALLOON:
		dev->name = virtio_pci_balloon_name;
		break;
	case VIRTIO_TRANS_ID_CONSOLE:
		dev->name = virtio_pci_serial_name;
		break;
	case VIRTIO_TRANS_ID_RNG:
		dev->name = virtio_pci_rng_name;
		break;
	case PCI_DEVICE_NON_TRANSITIONAL(VIRTIO_ID_INPUT):
		dev->name = virtio_pci_input_name;
		break;
	case PCI_DEVICE_NON_TRANSITIONAL(VIRTIO_ID_GPU):
		dev->name = virtio_pci_gpu_name;
		break;
	default:
		ERROR("device type not supported!\n");
		return -ENOTSUP;
	}

	dev->id = dev_id;

	return 0;
}

int virtio_pci_ecam_set_bar(struct virtio_pci_device *dev, uint32_t bar,
			    uint32_t value, int write)
{
	uint32_t addr;
	int bari = PCIE_MAX_BAR;

	switch (bar) {
	case PCI_BASE_ADDRESS_0:
		bari = 0;
		break;
	case PCI_BASE_ADDRESS_1:
		bari = 1;
		break;
	case PCI_BASE_ADDRESS_2:
		bari = 2;
		break;
	case PCI_BASE_ADDRESS_3:
		bari = 3;
		break;
	case PCI_BASE_ADDRESS_4:
		bari = 4;
		break;
	case PCI_BASE_ADDRESS_5:
		bari = 5;
		break;
	default:
		break;
	}

	if (write) {
		dev->bar[bari].start = value;

		if (value == 0xFFFFFFFF)
			return 0;
		if ((value & PCI_BASE_ADDRESS_MEM_TYPE_MASK) ==
		    PCI_BASE_ADDRESS_MEM_TYPE_64)
			return 0;
		addr = value & PCI_BASE_ADDRESS_MEM_MASK;
		/* 64 bit entry */
		if (bari && ((dev->bar[bari-1].start & PCI_BASE_ADDRESS_MEM_TYPE_MASK) ==
		    PCI_BASE_ADDRESS_MEM_TYPE_64)) {
			dev->bar[bari-1].start |= ((uint64_t)value << 32);
			dev->bar[bari-1].start &= PCI_BASE_ADDRESS_MEM_MASK;
		}
	} else {
		addr = value & PCI_BASE_ADDRESS_MEM_MASK;
		/* If this was a size query */
		if (dev->bar[bari].start == 0xFFFFFFFF)
			dev->bar[bari].size = (((uint32_t)~addr) + 1);
	}

	return 0;
}

int virtio_pci_ecam_add_capability(struct virtio_pci_device *dev,
				   uint8_t cap_offt, uint32_t value)
{
	int i;
	struct virtio_pci_cap *cap = NULL;
	uint8_t cap_field, cap_len;

	/* Virtio capability access */
	for (i = 0; i < PCIE_MAX_CAP; i++) {

		if (!dev->cap_cfg[i].base) {
			ERROR("    unknown capability access 0x%x\n",
			      cap_offt);
			break;
		}

		if (dev->cap_cfg[i].cap.cap_vndr != PCI_CAP_ID_VNDR)
			continue;

		cap_len = sizeof(struct virtio_pci_cap);
		/*
		 * Notifier multiplier is an extra 32 bit field
		 * after the capability.
		 */
		if (dev->cap_cfg[i].cap.cfg_type == VIRTIO_PCI_CAP_NOTIFY_CFG)
			cap_len += sizeof(uint32_t);

		/* Check if this is within a virtio capability field */
		if ((cap_offt >= dev->cap_cfg[i].base) &&
		    (cap_offt < (dev->cap_cfg[i].base + cap_len))) {
			cap_field = cap_offt - dev->cap_cfg[i].base;
			cap = &dev->cap_cfg[i].cap;
			break;
		}
	}

	if (cap == NULL)
		return -ENOENT;

	switch (cap_field) {
	case VIRTIO_PCI_CAP_VNDR:
	case VIRTIO_PCI_CAP_NEXT:
		/* We should have these two already */
		LOG("    ecam cap 0x%llx field: 0x%x val: 0x%llx\n",
		    cap, cap_field, value);
		break;
	case VIRTIO_PCI_CAP_LEN:
		cap->cap_len = value;
		break;
	case VIRTIO_PCI_CAP_CFG_TYPE:
		cap->cfg_type = value;
		break;
	case VIRTIO_PCI_CAP_BAR:
		cap->bar = value;
		break;
	case VIRTIO_PCI_CAP_OFFSET:
		cap->offset = value;
		break;
	case VIRTIO_PCI_CAP_LENGTH:
		cap->length = value;
		break;
	case VIRTIO_PCI_NOTIFY_CAP_MULT:
		dev->notify_off_multiplier = value;
		break;
	default:
		LOG("    unknown offset 0x%x\n", cap_offt);
		break;
	}
	return 0;
}

int virtio_pci_ecam_add_next_ptr(struct virtio_pci_device *dev,
				    uint32_t cap_offt, uint32_t value)
{
	int i;

	/* Config offset access */
	for (i = 0; i < (PCIE_MAX_CAP - 1); i++) {
		if (!dev->cap_cfg[i].cap.cap_next)
			break;
		if (cap_offt != dev->cap_cfg[i].cap.cap_next)
			continue;
		/* This was a read to capability base offset */
		dev->cap_cfg[i+1].base = cap_offt;
		dev->cap_cfg[i+1].cap.cap_next = VIRTIO_PCI_CAP_NEXT_PTR(value);
		dev->cap_cfg[i+1].cap.cap_vndr = VIRTIO_PCI_CAP_VENDOR(value);
		return 0;
	}

	return -ENOENT;
}

int virtio_pci_ecam_capability(struct virtio_pci_device *dev, uint32_t cap_offt,
			       uint32_t value)
{
	if (!virtio_pci_ecam_add_next_ptr(dev, cap_offt, value))
		return 0;

	return virtio_pci_ecam_add_capability(dev, cap_offt, value);
}

void virtio_pci_ecam_config(void *g, void *c)
{
	uint64_t value, devidx;
	uint16_t ecam_word;
	struct virtio_common_io *vcio;
	struct virtio_pci_device *dev = NULL;
	struct kvm_guest *guest = (struct kvm_guest *)g;
	struct vcpu_context *ctxt = (struct vcpu_context *)c;

	vcio = &ctxt->vcio;
	value = ctxt->regs.regs[vcio->reg];

	devidx = PCIE_ECAM_DEV(vcio->addr);
	if (devidx > MAX_VIRTIO_PCI_DEVS) {
		ERROR("out of virtio device slots!\n");
		return;
	}
	dev = &guest->virtio_pci_dev[devidx];

	if (!dev->id) {
		/*
		 * We are not familiar with this beast yet.
		 * Check if we can do something about it now.
		 */
		if (!vcio->wnr && IS_PCIE_ECAM_DEVROOT(vcio->addr) &&
		   (PCI_VENDOR_ID(value) == PCI_VENDOR_ID_REDHAT_QUMRANET)) {
			if (!virtio_pci_ecam_set_device(dev, PCI_DEVICE_ID(value)))
				LOG("    %s at 0x%llx id:0x%lx): 0x%llx\n", dev->name, vcio->addr, dev->id,  value);
		}
	}

	if (!dev->id) {
		ERROR("unknown access: 0x%llx\n", vcio->addr);
		return;
	}

	if (PCIE_ECAM_FUNCTION(vcio->addr) != 0) {
		ERROR("unknown function: 0x%llx\n", vcio->addr);
		return;
	}

	ecam_word = PCIE_ECAM_WORD(vcio->addr);

	if ((ecam_word >= PCI_BASE_ADDRESS_0) &&
	    (ecam_word <= PCI_BASE_ADDRESS_5)) {
		virtio_pci_ecam_set_bar(dev, ecam_word, value, vcio->wnr);
		return;
	}

	switch (ecam_word) {
	case PCI_HEADER_TYPE:
		if (!vcio->wnr)
			dev->header_type = PCI_HEADER_TYPE_VAL(value);
		return;
	case PCI_CAPABILITY_LIST:
		if (vcio->wnr)
			return;
		if (!dev->cap_cfg[VIRTIO_PCI_LIST_SIDX].cap.cap_next) {
			dev->cap_cfg[VIRTIO_PCI_LIST_SIDX].base = ecam_word;
			dev->cap_cfg[VIRTIO_PCI_LIST_SIDX].cap.cap_next = value;
		}
		return;
	}

	if (dev->header_type != PCI_HEADER_TYPE_NORMAL) {
		ERROR("header type not supported: 0x%llx\n", dev->header_type);
		return;
	}
	/*
	 * Add standard configuration header access handling above this comment
	 * line.
	 */
	if (ecam_word <= PCI_STD_HEADER_END)
		return;

	if (!vcio->wnr)
		virtio_pci_ecam_capability(dev, ecam_word, value);

	return;
}
