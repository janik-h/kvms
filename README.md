******************************************************************************
KVM compatible ARM64 hypervisor
******************************************************************************

KVM hypervisor variant that can do TDX/SEV like security for existing armv8
systems. The hypervisor is implemented such that it can function in almost
any armv8 board out there with virtualization support, regardless of the fact
if the system shipped with existing EL2 elements or not.

Features added over regular KVM configurations are:
- Nearly full guest and host memory space separation
- Complete, linear guest memory integrity protection. Guest pages remain
  intact and unmovable but they can still be swapped in/out when needed.
- Host swap encryption
- Guest memory AES encrypted swapping
- Guest kernel signature verification support
- Kernel memory protection toolchain:
  - Page table locks (including elements inside the P?Ds)
  - Memory region permission adjustments
- Memory region / permission validation tools for all CPU modes
- Hypervisor internal key generation functionality and keyring for guest
  specific keys (filesystem encryption, integrity, ..)
- Initial support for secure guest migration via a shared secret
- Easy hooks into the hardware security features via symbol overrides


Building and running on QEMU:
-----------------------------
- Run 'make tools'. This will build all the tools required with right versions
  and install them into the 'buildtools' directory. This will also build the
  patched kernel under oss/linux.
- Run 'make target-qemu' to generate a qemu binary for the host invocation
- Run 'make hostimage' to generate a virtualization system host image
- Run 'make guestimage' to generate a sample virtualized guest for testing
- Confirm whether PLATFORM and BOOTIMG env variables set correct value.
  or set environment variable BOOTIMG to point to the image. Set PLATFORM
  as well to tell the build system which target you are going for.
  These variables are set in run scripts under docker directory.
- Run 'make DEBUG=1' to build the hypervisor against the kernel under oss/linux
- 'make run' will run the host emulation
- 'make gdb' will run a target debugger session. You can hit breakpoints
  anywhere in the kernel and in the hypervisor. This implies that that 'run'
  target was invoked with 'make DEBUGGER=1 run' such that the QEMU was waiting
  for the debugger connection.
- 'make GRAPHICS=1 ... run' will enable a spice display for the host. The
  invocation will echo the correct connection endpoint to connect to.
- Install more kvm virtual machines inside your host system emulation to see
  some more work the hypervisor is doing.
- Work with the kernel under oss/linux, hyp


Host <-> Guest separation
-------------------------
- Once guest touches a page, it is removed from the host. This is true for
  all guest pages.
- ARmv8 guests are extended to do 'set memory {encrypted, decrypted}' calls
- Guest is always responsible for opening the shared communication channels


Secure guest swap
-----------------
- The support is experimental. High level logic is as follows:
  - When the linux mm evicts a clean page, we measure it (sha256) to make sure
    it can't change while the vm doesn't own it. Besides the actual page data,
    we also measure the page permissions so that the page cannot change from RO
    to RW once being reloaded.
  - When the mm evicts a dirty page, we encrypt AND measure it on its way to the
    swap. We don't use the authenticated encryption as the measurement code has
    to be in place anyway to handle the clean / RO pages.


Secure host swap
----------------
- Hooks into kernel arch_do_swap_page, arch_unmap_one as full-swap encryption
  alternative to plain guest swap encryption
- Encrypts all pages going out to swap and decrypts them during swap-in
- Works in STANDALONE mode as well without virtualization support enabled
- Support is experimental


Guest kernel signature verification support
-------------------------------------------
- Hypervisor supports guest kernel signature checks out of the box. Just use
  two top level makefile targets ('gen_key' and 'sign_guest IMAGE=<file>
  DTB_FILE=<dtb_file> DTB_ADDR=<dtb load address>') to embed a signature of
  the kernel image and the device tree into the kernel image. The signature
  is checked prior to allowing the guest to be mapped as an executable.
- Actual work happens via embedded kernel loader that maps the kernel into
  guest memory space for the signature verification purposes prior to running.


VCPU protection
---------------
KVM stores the VCPU context (i.e. registers) in the architecture specific part
of the kvm_vcpu struct. The context is

- Used by the KVM itself in HW, MMIO and instruction emulation, specifically
  mrs, msr, hvc and smc instructions
- Accessible by userspace via KVM_SET_ONE_REG and KVM_GET_ONE_REG ioctls,
  primarily to initialize a guest

The project attempts to limit the exposure of the context outside the guest
once the guest initialization phase is done. To do this, the context is moved
to hypervisor. KVM MMIO and instruction emulation still work on the existing
VCPU context. This is selectively synchronized with the hypervisor VCPU
context. On guest exit, the hypervisor updates the KVM context, and on guest
entry, the hypervisor updates the hypervisor context as follows:

|              | Copy hyp -> KVM    | Copy KVM -> hyp      |
|--------------|--------------------|----------------------|
| hvc          | hvc args (x0...x3) | hvc return code (x0) |
| MMIO read    | -                  | load target reg      |
| MMIO write   | store source reg   | -                    |
| sysreg read  | -                  | mrs target reg       |
| sysreg write | msr source reg     | -                    |

Guest system state is stored in both hyp and VCPU context. Several of the
system registers are emulated and full access from KVM is required.

TBC: Floating point registers, QEMU state sync breakage


SHORT TERM TODO
----------------
1) Memory pressure testing
2) Hardened / versatile guest config and patches. We need guest configs and
   patches for various use cases. XHCI USB emulation support currently is one
   big hack (works but is insecure).
   https://github.com/intel/tdx/blob/guest/arch/x86/kernel/tdx-filter.c
3) Migration support
4) QEMU protected guest support to give the madvise() hint to KSM not to scan
   the guest memory: -cpu=host,protected-guest-support=kvms
5) Guest separation via virtio parsing
6) Read-only host kernel (stage2 locked stage1 page tables)
