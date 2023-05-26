/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef __HYP_API__
#define __HYP_API__

#ifndef __ASSEMBLY__
/*
 * Kernel-visible struct pointer to call security critical operations
 * from the kernel EL2 blob.
 */
struct hyp_extension_ops {
	int	(*load_host_stage2)(void);
	int	(*load_guest_stage2)(uint64_t vmid);
	void	(*save_host_traps)(void);
	void	(*restore_host_traps)(void);
	void	*(*hyp_vcpu_regs)(uint64_t vmid, uint64_t vcpuid);
	uint64_t (*guest_enter)(void *vcpu);
	void	(*sysreg_restore_guest)(uint64_t vmid, uint64_t vcpuid);
	void	(*sysreg_save_guest)(uint64_t vmid, uint64_t vcpuid);
};
#define KVMS_SYMPFX(name) __kvms_##name
#define NVHE_SYMPFX(name) __kvm_nvhe_##name
#define _WEAK_ALIAS(name, aliasname) \
	extern __typeof (name) aliasname __attribute__ ((weak, alias (#name)));
#define WEAK_ALIAS(name, aliasname) _WEAK_ALIAS (name, aliasname)
#define KVMS_SYMBOL(name) WEAK_ALIAS(name, KVMS_SYMPFX(name))
#endif

/*
 * Chunk granularity for extending runtime hypervisor memory
 */
#define HYP_CHUNK_SIZE	SZ_1M

/*
 * Base addressing for data sharing
 */
#define KERNEL_MAP	0xFFFFFFF000000000
#define KERN_VA_MASK	0x0000000FFFFFFFFF
#define CALL_MASK	KERN_VA_MASK
#define KERNEL_BASE	0x4000000000

/*
 * Kernel lock flags
 */
#define HOST_STAGE1_LOCK		0x1
#define HOST_STAGE2_LOCK		0x2
#define HOST_KVM_CALL_LOCK		0x4
#define HOST_PT_LOCK			0x8
#define HOST_KVM_TRAMPOLINE_LOCK	0x10
#define HOST_STAGE1_EXEC_LOCK		0x20
#define	HOST_LOCKFLAG_MASK		0x3F

/*
 * Host protection support
 */
#define HYP_FIRST_HOSTCALL		0x8000
#define HYP_HOST_MAP_STAGE1		0x8000
#define HYP_HOST_MAP_STAGE2		0x8001
#define HYP_HOST_UNMAP_STAGE1		0x8002
#define HYP_HOST_UNMAP_STAGE2		0x8003
#define HYP_HOST_BOOTSTEP		0x8004
#define HYP_HOST_GET_VMID		0x8005
#define HYP_HOST_SET_LOCKFLAGS		0x8006
#define HYP_HOST_PREPARE_STAGE1		0x8007
#define HYP_HOST_PREPARE_STAGE2		0x8008
#define HYP_HOST_SWAP_PAGE		0x8009
#define HYP_HOST_RESTORE_SWAP_PAGE	0x800A
#define HYP_LAST_HOSTCALL		HYP_HOST_RESTORE_SWAP_PAGE

/*
 * KVM guest support
 */
#define HYP_FIRST_GUESTCALL		0x9000
#define HYP_READ_MDCR_EL2		0x9000
#define HYP_SET_HYP_TXT			0x9001
#define HYP_SET_TPIDR			0x9002
#define HYP_INIT_GUEST			0x9003
#define HYP_FREE_GUEST			0x9004
#define HYP_UPDATE_GUEST_MEMSLOT	0x9005
#define HYP_GUEST_MAP_STAGE2		0x9006
#define HYP_GUEST_UNMAP_STAGE2		0x9007
#define HYP_USER_COPY			0x9009
#define HYP_MKYOUNG			0x900A
#define HYP_SET_GUEST_MEMORY_OPEN	0x900B
#define HYP_SET_GUEST_MEMORY_BLINDED	0x900C
#define HYP_MKOLD			0x900D
#define HYP_ISYOUNG			0x900E
#define HYP_TRANSLATE			0x900F
#define HYP_SET_MEMCHUNK		0x9010
#define HYP_RELEASE_MEMCHUNK		0x9011
#define HYP_GUEST_VCPU_REG_RESET	0x9012
#define HYP_GUEST_MEMMAP		0x9013
#define HYP_STOP_GUEST			0x9014
#define HYP_RESUME_GUEST		0x9015
#define HYP_GUEST_CACHE_OP		0x9020
#define HYP_REGION_PROTECT		0x9021
#define HYP_GET_CONFIG_PAGE		0x9022
/*
 * Optional - for debug only.
 */
#define HYP_READ_LOG			0xA000
#define HYP_SYNC_GPREGS			0xA001

/*
 * Guest specific key support
 */
#define HYP_GENERATE_KEY		0xB000
#define HYP_GET_KEY			0xB001
#define HYP_DELETE_KEY			0xB002
#define HYP_SAVE_KEYS			0xB003
#define HYP_LOAD_KEYS			0xB004
#define HYP_DEFINE_GUEST_ID		0xB005
#define HYP_GUEST_INIT_IMAGE_CHECK	0xB006
#define HYP_GUEST_DO_IMAGE_CHECK	0xB007
#define HYP_GUEST_REMAP_LOADER		0xB009
#define HYP_GUEST_GET_DERIVED_KEY	0xB010
#define HYP_LAST_GUESTCALL		HYP_GUEST_GET_DERIVED_KEY
#define STR(x) #x
#define XSTR(s) STR(s)

#ifndef __ASSEMBLY__
extern int __kvms_hvc_cmd(unsigned long cmd, ...);
extern uint64_t __kvms_hvc_get(unsigned long cmd, ...);
#endif // __ASSEMBLY__

#endif // __HYP_API__
