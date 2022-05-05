/* SPDX-License-Identifier: GPL-2.0-only */

#ifndef __PCI_H__
#define __PCI_H__

#include <stdint.h>
#include <stdbool.h>
#include "virtio_pci.h"
#include "virtio.h"

/*
 * How many devices we are willing to accommodate per guest.
 * Max from specification (per bus) is 32.
 */
#define MAX_VIRTIO_PCI_DEVS 32

/* Virtio ID */
#define PCI_DEVICE_IS_TRANSITIONAL(x)	!(!((x) & 0x1000))
#define PCI_DEVICE_NON_TRANSITIONAL(x)	((x) + 0x1040)

/* Virtio PCI vendor */
#define PCI_VENDOR_ID_REDHAT_QUMRANET	0x1af4
#define  PCI_CAP_ID_VNDR	0x09

#define IS_PCIE_ECAM_DEVROOT(x)	!((x) & 0xFFFUL)

#define PCI_VENDOR_MASK		0xFFFF
#define PCI_VENDOR_ID(x)	((x) & PCI_VENDOR_MASK)

#define PCI_DEVICE_MASK		0xFFFF
#define PCI_DEVICE_SHIFT	16
#define PCI_DEVICE_ID(x)	(((x) >> PCI_DEVICE_SHIFT) & PCI_DEVICE_MASK)

/* ECAM addressing scheme */
#define PCIE_ECAM_BASEMASK	0xFFFFFFFFF0000000UL
#define PCIE_ECAM_BASE(x)	((x) & PCIE_ECAM_BASEMASK)

#define PCIE_ECAM_BUSMASK	0xFFUL
#define PCIE_ECAM_BUSSHIFT	20
#define PCIE_ECAM_BUS(x)	(((x) >> PCIE_ECAM_BUSSHIFT) & PCIE_ECAM_BUSMASK)

#define PCIE_ECAM_DEVMASK	0x1FUL
#define PCIE_ECAM_DEVSHIFT	15
#define PCIE_ECAM_DEV(x)	(((x) >> PCIE_ECAM_DEVSHIFT) & PCIE_ECAM_DEVMASK)

#define PCIE_ECAM_FNMASK	0x7UL
#define PCIE_ECAM_FNSHIFT	12
#define PCIE_ECAM_FUNCTION(x)	(((x) >> PCIE_ECAM_FNSHIFT) & PCIE_ECAM_FNMASK)

#define PCIE_ECAM_WMASK		0x3FFUL
#define PCIE_ECAM_WORD(x)	((x) & PCIE_ECAM_WMASK)

/* ECAM start byte */
#define PCIE_ECAM_SBMASK	0x3UL
#define PCIE_ECAM_SBYTE(x)	((x) & PCIE_ECAM_SBMASK)

/* PCI standard configuration header part (first 64 bytes) */
#define PCI_STD_HEADER_END	0x3f
/* Base addresses */
#define PCIE_MAX_BAR	6
#define PCI_BASE_ADDRESS_0	0x10
#define PCI_BASE_ADDRESS_1	0x14
#define PCI_BASE_ADDRESS_2	0x18
#define PCI_BASE_ADDRESS_3	0x1c
#define PCI_BASE_ADDRESS_4	0x20
#define PCI_BASE_ADDRESS_5	0x24
#define PCI_BASE_ADDRESS_MEM_TYPE_MASK	0x06
#define PCI_BASE_ADDRESS_MEM_TYPE_64	0x04
#define PCI_BASE_ADDRESS_MEM_MASK	(~0x0fUL)
/* Header type */
#define PCI_HEADER_TYPE		0x0e
#define PCI_HEADER_TYPE_MASK	0x7f
#define PCI_HEADER_TYPE_VAL(x)	((x) & PCI_HEADER_TYPE_MASK)
#define PCI_HEADER_TYPE_NORMAL	0

/* Capability list pointer */
/* virtio pci capabilities */
#define PCIE_MAX_CAP			12
#define VIRTIO_PCI_LIST_START		6
#define VIRTIO_PCI_LIST_SIDX		0
#define PCI_CAPABILITY_LIST		0x34
#define VIRTIO_PCI_CAP_VENDOR(x)	((x) & 0xFF)
#define VIRTIO_PCI_CAP_NEXT_PTR(x)	(((x) & 0xFF00) >> 8)

/*#define VIRTIO_PCI_IS_CAP_PTR(x)	!((x) & 0xF)*/

struct virtio_pci_bar {
	uint64_t start;
	uint64_t size;
};

struct virtio_pci_cap_cfg {
	uint8_t base;
	struct virtio_pci_cap cap;
};

struct virtio_pci_device {
	uint16_t id;
	uint8_t header_type;
	uint8_t cap_ptr;
	const char *name;
	uint32_t confbar;
	uint32_t notify_off_multiplier;
	struct virtio_pci_bar bar[PCIE_MAX_BAR];
	struct virtio_pci_common_cfg common_cfg;
	struct virtio_pci_cap_cfg cap_cfg[PCIE_MAX_CAP];
	struct virtio_queueset vqs;
};

/*moveme?*/
struct virtio_common_io {
	struct virtio_pci_device *dev;
	uint64_t addr;
	uint8_t reg;
	uint8_t wnr;
};

void virtio_pci_ecam_config(void *g, void *c);

/* PCI device (bar) aborts */
struct virtio_pci_device *virtio_pci_device_get(void *g,
						uint64_t ipa,
						bool *common_access);

void virtio_pci_access(void *c);
void virtio_pci_scan(void *g, void *c);
void virtio_pci_notify_check(void *g, void *c);

/* Device tree functions */
int dtb_populate_virtio_pci_devices(void *g);

void virtio_scan_avail_rings(void *g);

#endif // __PCI_H__
