/* SPDX-License-Identifier: GPL-2.0-only */

#ifndef __SYS_CONTEXT_H__
#define __SYS_CONTEXT_H__

#include <stdint.h>
#include "pt_regs.h"
#include "pci.h"

typedef struct {
	uint64_t vttbr_el2;
	uint64_t vtcr_el2;
	uint64_t ttbr0_el1;
	uint64_t ttbr1_el1;
	uint64_t hcr_el2;
	uint64_t cptr_el2;
	uint64_t mdcr_el2;
	uint64_t hstr_el2;
} sys_context_t;

struct nvhe_sysregs {
	uint64_t mpidr_el1;
	uint64_t csselr_el1;
	uint64_t cpacr_el1;
	uint64_t ttbr0_el1;
	uint64_t ttbr1_el1;
	uint64_t tcr_el1;
	uint64_t esr_el1;
	uint64_t afsr0_el1;
	uint64_t afsr1_el1;
	uint64_t far_el1;
	uint64_t mair_el1;
	uint64_t vbar_el1;
	uint64_t contextidr_el1;
	uint64_t amair_el1;
	uint64_t cntkctl_el1;
	uint64_t par_el1;
	uint64_t tpidr_el1;
	uint64_t sp_el1;
	uint64_t elr_el1;
	uint64_t spsr_el1;
	uint64_t mdscr_el1;
	uint64_t tpidr_el0;
	uint64_t tpidrro_el0;
};

enum pc_sync {
	PC_SYNC_NONE = 0,
	PC_SYNC_SKIP = 1,
	PC_SYNC_COPY = 2,
};

struct vcpu_context {
	struct user_pt_regs regs;
	struct user_pt_regs *kvm_regs;
	uint32_t gpreg_sync_from_kvm;
	enum pc_sync pc_sync_from_kvm;
	struct nvhe_sysregs state;
	struct virtio_common_io vcio;
};

#endif // __SYS_CONTEXT_H__
