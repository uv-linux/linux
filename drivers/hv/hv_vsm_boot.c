// SPDX-License-Identifier: GPL-2.0
/*
 * VSM boot framework that enables VTL1, loads secure kernel
 * and boots VTL1.
 *
 * Copyright (c) 2023, Microsoft Corporation.
 *
 */

#include <linux/hyperv.h>
#include <linux/kthread.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/cpumask.h>
#include <linux/vmalloc.h>
#include <linux/verification.h>
#include <crypto/pkcs7.h>

#include <asm/mshyperv.h>

#include "hv_vsm.h"

/* Define PAGE size and related variables for initial secure kernel pages */
#define VSM_PAGE_SHIFT  12
#define VSM_PAGE_SIZE  (((uint32_t)1) << VSM_PAGE_SHIFT)
#define PAGE_AT(addr, idx) ((addr) + (idx) * VSM_PAGE_SIZE)
#define VSM_VA_FROM_PA(pa) (pa)	// Assumes identity mapping in secure kernel

#define VSM_PAGE_MASK (_PAGE_PRESENT | _PAGE_RW)
#define VSM_PAGE_PTE_MASK (VSM_PAGE_MASK | _PAGE_ACCESSED | _PAGE_DIRTY)

/* Number of entries in a page table (all levels) */
#define VSM_ENTRIES_PER_PT	512
/* Shifts to compute page table mapping */
#define VSM_PD_TABLE_SHIFT      21
#define VSM_PDP_TABLE_SHIFT     30
#define VSM_PML4_TABLE_SHIFT    39

/* Helpers to convert kernel virtual address to PAs and vice versa */
#define VSM_NON_LOGICAL_PHYS_TO_VIRT(pa) ((pa) - vsm_skm_pa + vsm_skm_va)
#define VSM_NON_LOGICAL_VIRT_TO_PHYS(va) ((va) - vsm_skm_va + vsm_skm_pa)

/* Given VA, get index into the page table at a given level */
#define VSM_GET_PML4_INDEX_FROM_VA(va) (((va) >> VSM_PML4_TABLE_SHIFT) & 0x1FF)
#define VSM_GET_PDP_INDEX_FROM_VA(va) (((va) >> VSM_PDP_TABLE_SHIFT) & 0x1FF)
#define VSM_GET_PD_INDEX_FROM_VA(va) (((va) >> VSM_PD_TABLE_SHIFT) & 0x1FF)

/*
 * Initial memory that will be mapped for secure kernel.
 * Secure Kernel memory can be larger than this.
 */
#define VSM_SK_INITIAL_MAP_SIZE	(16 * 1024 * 1024)
#define VSM_FIRST_CODE_PAGE    0
#define VSM_GDT_PAGE           4081
#define VSM_TSS_PAGE           4083
#define VSM_PML4E_PAGE         4084
#define VSM_PDPE_PAGE          4085
#define VSM_PDE_PAGE           4086
#define VSM_PTE_0_PAGE         4087
#define VSM_KERNEL_STACK_PAGE  4095  // 4Kb stack

#define HV_VTL1_ENABLE_BIT      BIT(1)

#define VSM_BOOT_SIGNAL	0xDC
#define VSM_MAX_BOOT_CPUS	96

static struct file *sk_loader, *sk;
static struct page *boot_signal_page, *cpu_online_page, *cpu_present_page;
#ifndef CONFIG_HYPERV_VSM_DISABLE_IMG_VERIFY
static struct file *sk_loader_sig, *sk_sig;
#endif
static phys_addr_t vsm_skm_pa;
static void *vsm_skm_va;
static u8 *boot_signal;

bool hv_vsm_boot_success;
bool hv_vsm_mbec_enabled = true;

static int hv_vsm_get_partition_status(u16 *enabled_vtl_set, u8 *max_vtl, u16 *mbec_enabled_vtl_set)
{
	u64 result;
	int ret;
	union hv_register_vsm_partition_status vsm_partition_status = { 0 };

	ret = hv_vsm_get_register(HV_REGISTER_VSM_PARTITION_STATUS, &result);
	if (ret)
		return ret;

	vsm_partition_status = (union hv_register_vsm_partition_status)result;
	*enabled_vtl_set = vsm_partition_status.enabled_vtl_set;
	*max_vtl = vsm_partition_status.max_vtl;
	*mbec_enabled_vtl_set = vsm_partition_status.mbec_enabled_vtl_set;
	return 0;
}

static int hv_vsm_get_vp_status(u16 *enabled_vtl_set, u8 *active_mbec_enabled)
{
	u64 result;
	int ret;
	union hv_register_vsm_vp_status vsm_vp_status = { 0 };

	ret = hv_vsm_get_register(HV_REGISTER_VSM_VP_STATUS, &result);
	if (ret)
		return ret;

	vsm_vp_status = (union hv_register_vsm_vp_status)result;
	*enabled_vtl_set = vsm_vp_status.enabled_vtl_set;
	*active_mbec_enabled = vsm_vp_status.active_mbec_enabled;

	return 0;
}

#ifdef CONFIG_HYPERV_VSM_DEBUG
/* Walks page tables, starting at the PML4 (top level). */
static void hv_vsm_dump_pt(u64 root, int lvl)
{
	int n;

	u64 entry_pa;
	u64 *entry_va;
	u64 next_pa;

	if (lvl == 5)
		return;

	for (n = 0; n < VSM_ENTRIES_PER_PT; n++) {
		entry_pa = root + (n * sizeof(u64));
		entry_va = VSM_NON_LOGICAL_PHYS_TO_VIRT(entry_pa);

		if (*entry_va)
			pr_info("\t\t Entry: %i/%i - 0x%llx\n", n, lvl,
				*entry_va);

		if (*entry_va & VSM_PAGE_PRESENT) {
			next_pa = *entry_va & VSM_PAGE_BASE_ADDR_MASK;
			hv_vsm_dump_pt(next_pa, lvl + 1);
		}
	}
}

static void hv_vsm_dump_secure_kernel_memory(void)
{
	pr_info("%s: Dumping Secure Kernel Memory\n", __func__);
	print_hex_dump(KERN_INFO, "\t", DUMP_PREFIX_ADDRESS, 32, 4, (void *)vsm_skm_va, 1024, 0);
}
#endif

static void __init __hv_vsm_init_vtlcall(struct hv_vtlcall_param *args)
{
	u64 hcall_addr;

	hcall_addr = (u64)((u8 *)hv_hypercall_pg + vsm_code_page_offsets.vtl_call_offset);
	register u64 hypercall_addr asm("rax") = hcall_addr;

	asm __volatile__ (	\
	/* Keep copies of all the registers */
		"pushq	%%rdi\n"
		"pushq	%%rsi\n"
		"pushq	%%rdx\n"
		"pushq	%%rbx\n"
		"pushq	%%rcx\n"
		"pushq	%%rax\n"
		"pushq	%%r8\n"
		"pushq	%%r9\n"
		"pushq	%%r10\n"
		"pushq	%%r11\n"
		"pushq	%%r12\n"
		"pushq	%%r13\n"
		"pushq	%%r14\n"
		"pushq	%%r15\n"
		"pushq  %%rbp\n"
	/*
	 * The vtlcall_param structure is in rdi, which is modified below, so copy it into a
	 * register that stays constant in the instructon block immediately following.
	 */
		"movq	%1, %%r12\n"

	/* Copy values from vtlcall_param structure into registers used to communicate with VTL1 */
		"movq	0x00(%%r12), %%rdi\n"
		"movq	0x08(%%r12), %%rsi\n"
		"movq	0x10(%%r12), %%rdx\n"
		"movq	0x18(%%r12), %%r8\n"
	/* Make rcx 0 */
		"xorl	%%ecx, %%ecx\n"
	/* VTL call */
		CALL_NOSPEC
	/* Restore r12 with vtlcall_param after VTL call */
		"movq	112(%%rsp), %%r12\n"

	/* Copy values from registers used to communicate with VTL1 into vtlcall_param structure */
		"movq	%%rdi,  0x00(%%r12)\n"
		"movq	%%rsi,  0x08(%%r12)\n"
		"movq	%%rdx,  0x10(%%r12)\n"
		"movq	%%r8,  0x18(%%r12)\n"

	/* Restore all modified registers */
		"popq   %%rbp\n"
		"popq	%%r15\n"
		"popq	%%r14\n"
		"popq	%%r13\n"
		"popq	%%r12\n"
		"popq	%%r11\n"
		"popq	%%r10\n"
		"popq	%%r9\n"
		"popq	%%r8\n"
		"popq	%%rax\n"
		"popq	%%rcx\n"
		"popq	%%rbx\n"
		"popq	%%rdx\n"
		"popq	%%rsi\n"
		"popq	%%rdi\n"
		: ASM_CALL_CONSTRAINT
		: "D"(args), THUNK_TARGET(hypercall_addr)
		: "cc", "memory");
}

static int __init hv_vsm_init_vtlcall(struct hv_vtlcall_param *args)
{
	unsigned long flags = 0;
	u64 cr2;

	local_irq_save(flags);
	kernel_fpu_begin_mask(0);
	cr2 = native_read_cr2();
	__hv_vsm_init_vtlcall(args);
	native_write_cr2(cr2);
	kernel_fpu_end();
	local_irq_restore(flags);

	return (int)args->a3;
}

static __init void hv_vsm_boot_vtl1(void)
{
	struct hv_vtlcall_param args = {0};
	u16 vp_enabled_vtl_set = 0;
	u8 active_mbec_enabled = 0;

	args.a0 = num_possible_cpus();
	args.a1 = sk_res.start;
	args.a2 = sk_res.end + 1;
	args.a3 = max_pfn << PAGE_SHIFT;

	hv_vsm_init_vtlcall(&args);

	hv_vsm_get_vp_status(&vp_enabled_vtl_set, &active_mbec_enabled);
	if (!active_mbec_enabled) {
		pr_err("Failed to enable MBEC for VP0\n");
		hv_vsm_mbec_enabled = false;
	}
}

static u64 hv_vsm_establish_shared_page(struct page **page)
{
	void *va;

	*page = alloc_page(GFP_KERNEL);

	if (!(*page)) {
		pr_err("%s: Unable to establish VTL0-VTL1 shared page\n", __func__);
		return -ENOMEM;
	}

	va = page_address(*page);
	memset(va, 0, PAGE_SIZE);

	return page_to_pfn(*page);
}

static __init int hv_vsm_enable_ap_vtl(void)
{
	struct hv_vtlcall_param args = {0};
	u64 cpu_present_mask_pfn;
	void *va;
	int ret = 0;

	/* Allocate Present Cpumask Page & Copy cpu_present_mask */
	cpu_present_mask_pfn = hv_vsm_establish_shared_page(&cpu_present_page);

	if (cpu_present_mask_pfn < 0)
		return -ENOMEM;

	va = page_address(cpu_present_page);
	cpumask_copy((struct cpumask *)va, cpu_present_mask);

	args.a0 = VSM_VTL_CALL_FUNC_ID_ENABLE_APS_VTL;
	args.a1 = cpu_present_mask_pfn;

	ret = hv_vsm_init_vtlcall(&args);

	if (ret)
		pr_err("%s: Failed to enable VTL1 for APs. Error %d", __func__, ret);

	__free_page(cpu_present_page);
	return ret;
}

struct task_struct **ap_thread;
static __init int hv_vsm_boot_sec_vp_thread_fn(void *unused)
{
	struct hv_vtlcall_param args = {0};
	unsigned long flags = 0;
	int cpu = smp_processor_id(), next_cpu;
	u16 vp_enabled_vtl_set = 0;
	u8 active_mbec_enabled = 0;

	if (cpu > (VSM_MAX_BOOT_CPUS - 1)) {
		pr_err("CPU%d: Secure Kernel currently supports CPUID <= %d.",
		       smp_processor_id(), (VSM_MAX_BOOT_CPUS - 1));
		return -EINVAL;
	}

	pr_info("%s: cpu%d entering vtl1 boot thread\n", __func__, cpu);
	local_irq_save(flags);
	while (READ_ONCE(boot_signal[cpu]) != VSM_BOOT_SIGNAL) {
		if (kthread_should_stop()) {
			local_irq_restore(flags);
			goto out;
		}
	}

	local_irq_restore(flags);
	hv_vsm_init_vtlcall(&args);
out:
	next_cpu = cpumask_next(cpu, cpu_online_mask);
	if (next_cpu > 0 && next_cpu < nr_cpu_ids) {
		wake_up_process(ap_thread[next_cpu]);
		pr_info("%s: cpu%d exiting vtl1 boot thread. Waking up cpu%d\n",
			__func__, cpu, next_cpu);
	}

	hv_vsm_get_vp_status(&vp_enabled_vtl_set, &active_mbec_enabled);
	if (!active_mbec_enabled) {
		pr_err("Failed to enable MBEC for VP%d\n", cpu);
		hv_vsm_mbec_enabled = false;
	}
	return 0;
}

static __init int hv_vsm_boot_ap_vtl(void)
{
	struct hv_vtlcall_param args = {0};
	void *va;
	u64 boot_signal_pfn, cpu_online_mask_pfn;
	unsigned int cpu, cur_cpu = smp_processor_id(), vsm_cpus = num_possible_cpus(), next_cpu;
	int ret;

	/* Allocate & Initialize Boot Signal Page */
	boot_signal_pfn = hv_vsm_establish_shared_page(&boot_signal_page);

	if (boot_signal_pfn < 0)
		return -ENOMEM;

	va = page_address(boot_signal_page);
	boot_signal = (u8 *)va;
	boot_signal[0] = VSM_BOOT_SIGNAL;

	/* Allocate Online Cpumask Page & Copy cpu_online_mask */
	cpu_online_mask_pfn = hv_vsm_establish_shared_page(&cpu_online_page);

	if (cpu_online_mask_pfn < 0) {
		ret = -ENOMEM;
		goto free_bootsignal;
	}

	va = page_address(cpu_online_page);
	cpumask_copy((struct cpumask *)va, cpu_online_mask);

	/* Create per-CPU threads to do vtlcall and complete per-CPU hotplug boot in VTL1 */
	ap_thread = kmalloc_array(vsm_cpus, sizeof(*ap_thread), GFP_KERNEL);

	if (!ap_thread) {
		ret = -ENOMEM;
		goto free_sharedpages;
	}

	memset(ap_thread, 0, sizeof(*ap_thread) * vsm_cpus);

	for_each_online_cpu(cpu) {
		if (cpu == cur_cpu)
			continue;
		ap_thread[cpu] = kthread_create(hv_vsm_boot_sec_vp_thread_fn, NULL, "ap_thread");

		if (IS_ERR(ap_thread[cpu])) {
			ret = PTR_ERR(ap_thread[cpu]);
			goto out;
		}

		kthread_bind(ap_thread[cpu], cpu);
		sched_set_fifo(ap_thread[cpu]);
	}

	next_cpu = cpumask_next(cur_cpu, cpu_online_mask);
	if (next_cpu >= nr_cpu_ids)
		goto out;

	wake_up_process(ap_thread[next_cpu]);
	args.a0 = VSM_VTL_CALL_FUNC_ID_BOOT_APS;
	args.a1 = cpu_online_mask_pfn;
	args.a2 = boot_signal_pfn;

	ret = hv_vsm_init_vtlcall(&args);

	if (ret)
		pr_err("%s: Failed to boot APs for VTL1. Error %d", __func__, ret);
out:
	for_each_online_cpu(cpu) {
		if (ap_thread[cpu])
			kthread_stop(ap_thread[cpu]);
	}
	kfree(ap_thread);
free_sharedpages:
	__free_page(cpu_online_page);
free_bootsignal:
	__free_page(boot_signal_page);
	return ret;
}

static int __init hv_vsm_enable_partition_vtl(void)
{
	u64 status = 0;
	unsigned long flags;
	struct hv_input_enable_partition_vtl *hvin = NULL;

	local_irq_save(flags);

	hvin = *this_cpu_ptr(hyperv_pcpu_input_arg);
	memset(hvin, 0, sizeof(*hvin));

	hvin->partition_id = HV_PARTITION_ID_SELF;
	hvin->target_vtl.as_uint8 = 1;
	hvin->flags.enable_mbec = 1;

	status = hv_do_hypercall(HVCALL_ENABLE_PARTITION_VTL, hvin, NULL);

	if (status)
		pr_err("%s: Enable Partition VTL failed. status=0x%x\n",
		       __func__, hv_result(status));

	local_irq_restore(flags);

	return hv_result(status);
}

static int __init hv_vsm_reserve_sk_mem(void)
{
	void *va_start;
	struct page **page, **pages;
	unsigned long long paddr, sk_size;
	unsigned long size;
	int i, npages;

	if (!sk_res.start) {
		pr_err("%s: No memory reserved in cmdline for secure kernel", __func__);
		return -ENOMEM;
	}
	vsm_skm_pa = sk_res.start;
	vsm_skm_va = 0;

	/* Allocate an array of struct page pointers  */
	sk_size = sk_res.end - sk_res.start + 1;
	npages = sk_size >> PAGE_SHIFT;
	size = sizeof(struct page *) * npages;
	pages = vmalloc(size);

	if (!pages) {
		pr_err("%s: Allocating array of struct page pointers failed (Size: %lu)\n",
		       __func__, size);
		return -ENOMEM;
	}

	/*
	 * Convert each page frame number to struct page
	 * Memory was allocated using memblock_phys_alloc_range() during boot
	 */
	page = pages;
	paddr = vsm_skm_pa;
	for (i = 0; i < npages; i++) {
		*page++ = pfn_to_page(paddr >> PAGE_SHIFT);
		paddr += PAGE_SIZE;
	}

	/* Map Secure Kernel physical memory into kernel virtual address space */
	va_start = vmap(pages, npages, VM_MAP, PAGE_KERNEL);

	if (!va_start) {
		pr_err("%s: Memory mapping failed\n", __func__);
		vfree(pages);
		return -ENOMEM;
	}

	vsm_skm_va = va_start;

	pr_info("%s: secure kernel PA=0x%lx, VA=0x%lx\n",
		__func__, (unsigned long)vsm_skm_pa, (unsigned long)vsm_skm_va);

	memset(vsm_skm_va, 0, sk_size);
	vfree(pages);
	return 0;
}

static void __init hv_vsm_init_cpu(struct hv_init_vp_context *vp_ctx)
{
	/* Offset rip by any secure kernel header length */
	vp_ctx->rip = (u64)VSM_VA_FROM_PA(PAGE_AT(vsm_skm_pa,
		VSM_FIRST_CODE_PAGE));

	/* ToDo: Check if can be replaced with CR0_STATE */
	vp_ctx->cr0 =
		X86_CR0_PG |	// Paging
		X86_CR0_WP |	// Write Protect
		X86_CR0_NE |	// Numeric Error
		X86_CR0_ET |	// Extension Type
		X86_CR0_MP |	// Math Present
		X86_CR0_PE;	// Protection Enable

	vp_ctx->cr4 =
		X86_CR4_PSE |	// Page Size Extensions
		X86_CR4_PGE |	// Page Global Enable
		X86_CR4_PAE;	// Physical Address Extensions

	vp_ctx->efer =
		EFER_LMA |	// Long Mode Active
		EFER_LME |	// Long Mode Enable
		EFER_NX  |	// No Execute Enable
		EFER_SCE;	// System Call Enable

	/*
	 * Intel CPUs fail if the architectural read-as-one bit 1 of RFLAGS is not
	 * set. See Intel SDM Vol 3C, 26.3.1.4 (RFLAGS).
	 *
	 * TODO: Has Hyper-V implemented setting this automatically?
	 */
	vp_ctx->rflags = 0b10;

	vp_ctx->msr_cr_pat = 0x7040600070406;

#ifdef CONFIG_HYPERV_VSM_DEBUG
	pr_info("%s : Printing Initial VP Registers..\n", __func__);
	pr_info("\t\t RIP: 0x%llx\n", vp_ctx->rip);
	pr_info("\t\t CR0: 0x%llx\n", vp_ctx->cr0);
	pr_info("\t\t CR4: 0x%llx\n", vp_ctx->cr4);
	pr_info("\t\t EFER: 0x%llx\n", vp_ctx->efer);
	pr_info("\t\t RFLAGS: 0x%llx\n", vp_ctx->rflags);
	pr_info("\t\t CR PAT: 0x%llx\n", vp_ctx->msr_cr_pat);
#endif
}

static void __init hv_vsm_init_gdt(struct hv_init_vp_context *vp_ctx)
{
	phys_addr_t gdt_pa, tss_pa, kstack_pa;
	u64 tss_sk_va, gdt;
	struct x86_hw_tss *tss;
	size_t gdt_size = sizeof(gdt), tss_size = sizeof(*tss), gdt_offset = 0;

	/* Get a page for the GDT */
	gdt_pa = PAGE_AT(vsm_skm_pa, VSM_GDT_PAGE);
	/* Get a page for the TSS */
	tss_pa = PAGE_AT(vsm_skm_pa, VSM_TSS_PAGE);
	tss = VSM_NON_LOGICAL_PHYS_TO_VIRT(tss_pa);
	/* Compute the VA that secure kernele will see for the TSS */
	tss_sk_va = VSM_VA_FROM_PA(tss_pa);
	/* Get a page for the secure kernel initial stack */
	kstack_pa = PAGE_AT(vsm_skm_pa, VSM_KERNEL_STACK_PAGE);
	/* Set the initial stack pointer for the kernel to point to bottom of kernel stack */
	tss->sp0 = VSM_VA_FROM_PA(kstack_pa) + VSM_PAGE_SIZE - 1;
	vp_ctx->rsp = tss->sp0;

	/* Make and add the NULL descriptor to the GDT */
	gdt = GDT_ENTRY(0x2018, 0, 0);
	memcpy(VSM_NON_LOGICAL_PHYS_TO_VIRT(gdt_pa + gdt_offset), &gdt, gdt_size);
	gdt_offset += gdt_size;

	/* Make and add a code segment descriptor to the GDT */
	gdt = GDT_ENTRY(0x2098, 0, 0);
	memcpy(VSM_NON_LOGICAL_PHYS_TO_VIRT(gdt_pa + gdt_offset), &gdt, gdt_size);
	gdt_offset += gdt_size;

	/* Make and add a data segment descriptor to the GDT */
	gdt = GDT_ENTRY(0x90, 0, 0);
	memcpy(VSM_NON_LOGICAL_PHYS_TO_VIRT(gdt_pa + gdt_offset), &gdt, gdt_size);
	gdt_offset += gdt_size;

	/* Make and add a system segment descriptor for the TSS in the GDT */
	gdt = GDT_ENTRY(0x89, tss_sk_va, tss_size);
	memcpy(VSM_NON_LOGICAL_PHYS_TO_VIRT(gdt_pa + gdt_offset), &gdt, gdt_size);
	gdt_offset += gdt_size;

	/* Set up the GDT register */
	vp_ctx->gdtr.base = VSM_VA_FROM_PA(gdt_pa);
	vp_ctx->gdtr.limit = gdt_offset - 1;

	/* Set the code segment (CS) selector */
	vp_ctx->cs.base = 0;
	vp_ctx->cs.limit = 0;
	vp_ctx->cs.selector = 1 << 3;
	vp_ctx->cs.attributes = 0x209b;

	/* Set the data segment (DS) selector */
	vp_ctx->ds.base = 0;
	vp_ctx->ds.limit = 0;
	vp_ctx->ds.selector = 2 << 3;
	vp_ctx->ds.attributes = 0x4093;

	/* Set the ES, FS and GS to be the same as DS, for now */
	vp_ctx->es = vp_ctx->ds;
	vp_ctx->fs = vp_ctx->ds;
	vp_ctx->gs = vp_ctx->ds;

	/* Set the stack selector to 0 (unused in long mode) */
	vp_ctx->ss.selector = 0;

	/* Set the task register selector  */
	vp_ctx->tr.base = tss_sk_va;
	vp_ctx->tr.limit = tss_size - 1;
	vp_ctx->tr.selector = 3 << 3;
	vp_ctx->tr.attributes = 0x8b;

#ifdef CONFIG_HYPERV_VSM_DEBUG
	pr_info("%s Printing GDTR..\n", __func__);
	pr_info("\t\t Base:  0x%llx\n", vp_ctx->gdtr.base);
	pr_info("\t\t Limit: 0x%x\n",   vp_ctx->gdtr.limit);

	pr_info("%s Printing CS...\n", __func__);
	pr_info("\t\t Sel:   0x%x\n",   vp_ctx->cs.selector);
	pr_info("\t\t Base:  0x%llx\n", vp_ctx->cs.base);
	pr_info("\t\t Limit: 0x%x\n",   vp_ctx->cs.limit);
	pr_info("\t\t Attrs: 0x%x\n",   vp_ctx->cs.attributes);

	pr_info("%s: Printing DS/ES/FS/GS...\n");
	pr_info("\t\t Sel:   0x%x\n",   vp_ctx->ds.selector);
	pr_info("\t\t Base:  0x%llx\n", vp_ctx->ds.base);
	pr_info("\t\t Limit: 0x%x\n",   vp_ctx->ds.limit);
	pr_info("\t\t Attrs: 0x%x\n",   vp_ctx->ds.attributes);

	pr_info("%s: Printing TR...\n", __func__);
	pr_info("\t\t Sel:   0x%x\n",   vp_ctx->tr.selector);
	pr_info("\t\t Base:  0x%llx\n", vp_ctx->tr.base);
	pr_info("\t\t Limit: 0x%x\n",   vp_ctx->tr.limit);
	pr_info("\t\t Attrs: 0x%x\n",   vp_ctx->tr.attributes);
#endif
}

static void __init hv_vsm_fill_pte_tables(u64 *pde, int pd_index, int num_pte_tables)
{
	/*
	 * ToDo: Make a generic solution that can take any PA start and size and adjust
	 * the number of page tables and determine where to start filling them.
	 */
	u16 i, j;
	phys_addr_t pte_pa;
	u64 *pte;

	/* Fill page tables with entries */
	for (i = 0; i < num_pte_tables; i++) {
		pte_pa = PAGE_AT(vsm_skm_pa, VSM_PTE_0_PAGE + i);
		pte = VSM_NON_LOGICAL_PHYS_TO_VIRT(pte_pa);
		*(pde + pd_index + i) = pte_pa | VSM_PAGE_PTE_MASK;
		for (j = 0; j < VSM_ENTRIES_PER_PT; j++) {
			*(pte + j) =
				(vsm_skm_pa + ((j + (i * VSM_ENTRIES_PER_PT)) * VSM_PAGE_SIZE)) |
					VSM_PAGE_PTE_MASK;
		}
	}
}

static void __init hv_vsm_init_page_tables(struct hv_init_vp_context *vp_ctx)
{
	u64 pml4_index;
	u64 pdp_index;
	u64 pd_index;
	phys_addr_t pml4e_pa;
	phys_addr_t pdpe_pa;
	phys_addr_t pde_pa;
	u64 *pml4e;
	u64 *pdpe;
	u64 *pde;
	int num_pte_tables;

	/* Get offset to know where to start mapping. Note vsm_skm_pa is the VA for OP-TEE */
	pml4_index = VSM_GET_PML4_INDEX_FROM_VA(vsm_skm_pa);
	pdp_index = VSM_GET_PDP_INDEX_FROM_VA(vsm_skm_pa);
	pd_index = VSM_GET_PD_INDEX_FROM_VA(vsm_skm_pa);

#ifdef CONFIG_HYPERV_VSM_DEBUG
	pr_info("%s: pml4_index = 0x%llx, pdp_index = 0x%llx, pd_index=0x%llx\n",
		__func__, pml4_index, pdp_index, pd_index);
#endif

	pml4e_pa = PAGE_AT(vsm_skm_pa, VSM_PML4E_PAGE);
	pdpe_pa = PAGE_AT(vsm_skm_pa, VSM_PDPE_PAGE);
	pde_pa = PAGE_AT(vsm_skm_pa, VSM_PDE_PAGE);

	pml4e = VSM_NON_LOGICAL_PHYS_TO_VIRT(pml4e_pa);
	pdpe = VSM_NON_LOGICAL_PHYS_TO_VIRT(pdpe_pa);
	pde = VSM_NON_LOGICAL_PHYS_TO_VIRT(pde_pa);

	/* N.B.: Adding '+ 1' to a pointer moves the underlying value forward by 8 bytes! */
	*(pml4e + pml4_index) = pdpe_pa | VSM_PAGE_MASK;
	*(pdpe + pdp_index) = pde_pa | VSM_PAGE_MASK;

	/* Initial page tables map only the first VSM_SK_INITIAL_MAP_SIZE size of memory.
	 * This memory will be used for the Secure Loader and initial Secure Kernel
	 */
	num_pte_tables = (VSM_SK_INITIAL_MAP_SIZE / VSM_PAGE_SIZE) / VSM_ENTRIES_PER_PT;
	hv_vsm_fill_pte_tables(pde, pd_index, num_pte_tables);

	vp_ctx->cr3 = pml4e_pa;

#ifdef CONFIG_HYPERV_VSM_DEBUG
	pr_info("%s: Physical Range..\n", __func__);
	pr_info("\t\t Start: 0x%llx\n", vsm_skm_pa);
	pr_info("\t\t End:   0x%llx\n", vsm_skm_pa + VSM_SK_INITIAL_MAP_SIZE - 1);
	pr_info("%s: Page Table Physical Addresses\n", __func__);
	pr_info("\t\t PML4:   0x%llx\n", pml4e_pa);
	pr_info("\t\t PDPE:   0x%llx\n", pdpe_pa);
	pr_info("\t\t PDE:    0x%llx\n", pde_pa);
	pr_info("\t\t PTE 0: 0x%llx\n", PAGE_AT(vsm_skm_pa, VSM_PTE_0_PAGE));
	pr_info("\t\t PTE 1: 0x%llx\n", PAGE_AT(vsm_skm_pa, VSM_PTE_0_PAGE + 1));
	pr_info("\t\t PTE 2: 0x%llx\n", PAGE_AT(vsm_skm_pa, VSM_PTE_0_PAGE + 2));
	pr_info("\t\t PTE 3: 0x%llx\n", PAGE_AT(vsm_skm_pa, VSM_PTE_0_PAGE + 3));
	pr_info("%s: Page Table Dump\n", __func__);
	pr_info("\t\t Entry: Idx/Lvl - Raw Value\n");
	hv_vsm_dump_pt(pml4e_pa, 1);
#endif
}

static void __init hv_vsm_arch_init_vp_context(struct hv_init_vp_context *vp_ctx)
{
	hv_vsm_init_cpu(vp_ctx);
	hv_vsm_init_gdt(vp_ctx);
	hv_vsm_init_page_tables(vp_ctx);
}

static int __init hv_vsm_enable_vp_vtl(void)
{
	u64 status = 0;
	unsigned long flags;
	struct hv_enable_vp_vtl *hvin = NULL;

	hvin = *this_cpu_ptr(hyperv_pcpu_input_arg);
	memset(hvin, 0, sizeof(*hvin));

	hvin->partition_id = HV_PARTITION_ID_SELF;
	hvin->vp_index = HV_VP_INDEX_SELF;
	hvin->target_vtl.target_vtl = HV_VTL_SECURE;

	hv_vsm_arch_init_vp_context(&hvin->vp_context);

	local_irq_save(flags);

	status = hv_do_hypercall(HVCALL_ENABLE_VP_VTL, hvin, NULL);

	local_irq_restore(flags);

	return (int)(status & HV_HYPERCALL_RESULT_MASK);
}

#ifndef CONFIG_HYPERV_VSM_DISABLE_IMG_VERIFY
static int verify_vsm_signature(char *buffer, unsigned int buff_size, char *signature,
				unsigned int sig_size)
{
	int ret = 0;
	struct pkcs7_message *pkcs7;

	if (!buffer || !signature)
		return -EINVAL;
	pkcs7 = pkcs7_parse_message(signature, sig_size);
	if (IS_ERR(pkcs7)) {
		pr_err("%s: pkcs7_parse_message failed. Error code: %ld", __func__, PTR_ERR(pkcs7));
		return PTR_ERR(pkcs7);
	}
	ret = verify_pkcs7_signature(buffer, buff_size, signature, sig_size, NULL,
				     VERIFYING_UNSPECIFIED_SIGNATURE, NULL, NULL);
	if (ret) {
		pr_err("%s: verify_pkcs7_signature failed. Error code: %d", __func__, ret);
		return ret;
	}
	return ret;
}
#endif

static int __init hv_vsm_load_secure_kernel(void)
{
	/*
	 * Till we combine the skloader and kernel into one binary, we have to load them separately
	 * ToDo: Load them as one binary
	 */
	loff_t size_skloader, size_sk;
	char *skloader_buf = NULL, *sk_buf = NULL;
	int ret = 0;
#ifndef CONFIG_HYPERV_VSM_DISABLE_IMG_VERIFY
	loff_t size_skloader_sig, size_sk_sig;
	char *skloader_sig_buf = NULL, *sk_sig_buf = NULL;
#endif

	// Find the size of skloader and sk
	size_skloader = vfs_llseek(sk_loader, 0, SEEK_END);
	size_sk = vfs_llseek(sk, 0, SEEK_END);

#ifndef CONFIG_HYPERV_VSM_DISABLE_IMG_VERIFY
	size_skloader_sig = vfs_llseek(sk_loader_sig, 0, SEEK_END);
	size_sk_sig = vfs_llseek(sk_sig, 0, SEEK_END);
#endif

	// Seek back to the beginning of the file
	vfs_llseek(sk_loader, 0, SEEK_SET);
	vfs_llseek(sk, 0, SEEK_SET);

#ifndef CONFIG_HYPERV_VSM_DISABLE_IMG_VERIFY
	vfs_llseek(sk_loader_sig, 0, SEEK_SET);
	vfs_llseek(sk_sig, 0, SEEK_SET);
#endif

	// Allocate memory for the buffer
	skloader_buf = kvmalloc(size_skloader, GFP_KERNEL);
	if (!skloader_buf) {
		pr_err("%s: Unable to allocate memory for copying secure kernel\n", __func__);
		return -ENOMEM;
	}
	sk_buf = kvmalloc(size_sk, GFP_KERNEL);
	if (!sk_buf) {
		pr_err("%s: Unable to allocate memory for copying secure kernel\n", __func__);
		ret = -ENOMEM;
		goto free_skl;
	}

#ifndef CONFIG_HYPERV_VSM_DISABLE_IMG_VERIFY
	skloader_sig_buf = kvmalloc(size_skloader_sig, GFP_KERNEL);
	if (!skloader_sig_buf) {
		pr_err("%s: Unable to allocate memory for copying secure kernel\n", __func__);
		ret = -ENOMEM;
		goto free_sk;
	}
	sk_sig_buf = kvmalloc(size_sk_sig, GFP_KERNEL);
	if (!sk_sig_buf) {
		pr_err("%s: Unable to allocate memory for copying secure kernel\n", __func__);
		ret = -ENOMEM;
		goto free_skl_sig;
	}
#endif

	// Read from the file into the buffer
	ret = kernel_read(sk_loader, skloader_buf, size_skloader, &sk_loader->f_pos);
	if (ret != size_skloader) {
		pr_err("%s Unable to read skloader.bin file\n", __func__);
		goto free_bufs;
	}
	ret = kernel_read(sk, sk_buf, size_sk, &sk->f_pos);
	if (ret != size_sk) {
		pr_err("%s Unable to read vmlinux.bin file\n", __func__);
		goto free_bufs;
	}

#ifndef CONFIG_HYPERV_VSM_DISABLE_IMG_VERIFY
	ret = kernel_read(sk_loader_sig, skloader_sig_buf, size_skloader_sig,
			  &sk_loader_sig->f_pos);
	if (ret != size_skloader_sig) {
		pr_err("%s Unable to read skloader.bin.p7s file\n", __func__);
		goto free_bufs;
	}
	ret = kernel_read(sk_sig, sk_sig_buf, size_sk_sig, &sk_sig->f_pos);
	if (ret != size_sk_sig) {
		pr_err("%s Unable to read vmlinux.bin.p7s file\n", __func__);
		goto free_bufs;
	}

	ret = verify_vsm_signature(skloader_buf, size_skloader, skloader_sig_buf,
				   size_skloader_sig);

	if (ret) {
		pr_err("%s: Failed to verify Secure Loader signature.", __func__);
		goto free_bufs;
	}

	ret = verify_vsm_signature(sk_buf, size_sk, sk_sig_buf, size_sk_sig);

	if (ret) {
		pr_err("%s: Failed to verify Secure Kernel signature.", __func__);
		goto free_bufs;
	}
#endif

	memcpy(vsm_skm_va, skloader_buf, size_skloader);
	memcpy(vsm_skm_va + (2 * 1024 * 1024), sk_buf, size_sk);
	ret = 0;

free_bufs:
#ifndef CONFIG_HYPERV_VSM_DISABLE_IMG_VERIFY
	kvfree(sk_sig_buf);
free_skl_sig:
	kvfree(skloader_sig_buf);
free_sk:
#endif
	kvfree(sk_buf);
free_skl:
	kvfree(skloader_buf);
	return ret;
}

int __init hv_vsm_boot_init(void)
{
	cpumask_var_t mask;
	unsigned int boot_cpu;
	u16 partition_enabled_vtl_set = 0, partition_mbec_enabled_vtl_set = 0;
	u16 vp_enabled_vtl_set = 0;
	u8 partition_max_vtl, active_mbec_enabled = 0;
	int ret = 0;

	if (hv_vsm_reserve_sk_mem()) {
		pr_err("%s: Could not initialize memory for secure kernel\n", __func__);
		return -ENOMEM;
	}

	sk_loader = filp_open("/usr/lib/firmware/skloader.bin", O_RDONLY, 0);
	if (IS_ERR(sk_loader)) {
		pr_err("%s: File usr/lib/firmware/skloader.bin not found\n", __func__);
		ret = -ENOENT;
		goto free_mem;
	}
	sk = filp_open("/usr/lib/firmware/vmlinux.bin", O_RDONLY, 0);
	if (IS_ERR(sk)) {
		pr_err("%s: File usr/lib/firmware/vmlinux.bin not found\n", __func__);
		ret = -ENOENT;
		goto close_skl_file;
	}

#ifndef CONFIG_HYPERV_VSM_DISABLE_IMG_VERIFY
	sk_loader_sig = filp_open("/usr/lib/firmware/skloader.bin.p7s", O_RDONLY, 0);
	if (IS_ERR(sk_loader_sig)) {
		pr_err("%s: File usr/lib/firmware/skloader.bin.p7s not found\n", __func__);
		ret = -ENOENT;
		goto close_sk_file;
	}
	sk_sig = filp_open("/usr/lib/firmware/vmlinux.bin.p7s", O_RDONLY, 0);
	if (IS_ERR(sk_sig)) {
		pr_err("%s: File usr/lib/firmware/vmlinux.bin.p7s not found\n", __func__);
		ret = -ENOENT;
		goto close_skl_sig_file;
	}
#endif
	ret = hv_vsm_get_code_page_offsets();
	if (ret) {
		pr_err("%s: Unbable to retrieve vsm page offsets\n", __func__);
		goto close_files;
	}

	/*
	 * Copy the current cpu mask and pin rest of the running code to boot cpu.
	 * Important since we want boot cpu of VTL0 to be the boot cpu for VTL1.
	 * ToDo: Check if copying and restoring current->cpus_mask is enough
	 * ToDo: Verify the assumption that cpumask_first(cpu_online_mask) is
	 * the boot cpu
	 */
	if (!alloc_cpumask_var(&mask, GFP_KERNEL)) {
		pr_err("%s: Could not allocate cpumask", __func__);
		ret = -ENOMEM;
		goto close_files;
	}

	cpumask_copy(mask, &current->cpus_mask);
	boot_cpu = cpumask_first(cpu_online_mask);
	set_cpus_allowed_ptr(current, cpumask_of(boot_cpu));

	/* Check and enable VTL1 at the partition level */
	ret = hv_vsm_get_partition_status(&partition_enabled_vtl_set, &partition_max_vtl,
					  &partition_mbec_enabled_vtl_set);
	if (ret)
		goto out;

	if (partition_enabled_vtl_set & HV_VTL1_ENABLE_BIT) {
		pr_info("%s: Partition VTL1 is already enabled\n", __func__);
	} else {
		ret = hv_vsm_enable_partition_vtl();
		if (ret) {
			pr_err("%s: Enabling Partition VTL1 failed with status 0x%x\n",
			       __func__, ret);
			ret = -EINVAL;
			goto out;
		}
		hv_vsm_get_partition_status(&partition_enabled_vtl_set, &partition_max_vtl,
					    &partition_mbec_enabled_vtl_set);
		if (!(partition_enabled_vtl_set & HV_VTL1_ENABLE_BIT)) {
			pr_err("%s: Tried Enabling Partition VTL 1 and still failed", __func__);
			ret = -EINVAL;
			goto out;
		}
		if (!partition_mbec_enabled_vtl_set) {
			pr_err("%s: Tried Enabling Partition MBEC and failed", __func__);
			ret = -EINVAL;
			goto out;
		}
	}

	/* Check and enable VTL1 for the primary virtual processor */
	ret = hv_vsm_get_vp_status(&vp_enabled_vtl_set, &active_mbec_enabled);
	if (ret)
		goto out;

	if (vp_enabled_vtl_set & HV_VTL1_ENABLE_BIT) {
		pr_info("%s: VP VTL1 is already enabled\n", __func__);
	} else {
		ret = hv_vsm_enable_vp_vtl();
		if (ret) {
			pr_err("%s: Enabling VP VTL1 failed with status 0x%x\n", __func__, ret);
			/* ToDo: Should we disable VTL1 at partition level in this case */
			ret = -EINVAL;
			goto out;
		}
		hv_vsm_get_vp_status(&vp_enabled_vtl_set, &active_mbec_enabled);
		if (!(vp_enabled_vtl_set & HV_VTL1_ENABLE_BIT)) {
			pr_err("%s: Tried Enabling VP VTL 1 and still failed", __func__);
			ret = -EINVAL;
			goto out;
		}
	}

	ret = hv_vsm_load_secure_kernel();

	if (ret)
		goto out;

	/*
	 * Kick start vtl1 boot on primary cpu. There is currently no way to exit
	 * gracefully if this boot is not successful. In case of a failure, primary cpu
	 * will not return from vtl1 and system will hang.
	 */
	hv_vsm_boot_vtl1();

	/* Enable VTL1 for secondary processots */
	ret = hv_vsm_enable_ap_vtl();
	if (ret)
		goto out;

	/* Boot secondary processors in VTL1 */
	ret = hv_vsm_boot_ap_vtl();
	if (!ret) {
		hv_vsm_boot_success = true;
		hv_vsm_init_heki();
	}
out:
	set_cpus_allowed_ptr(current, mask);
	free_cpumask_var(mask);

close_files:
#ifndef CONFIG_HYPERV_VSM_DISABLE_IMG_VERIFY
	filp_close(sk_sig, NULL);
close_skl_sig_file:
	filp_close(sk_loader_sig, NULL);
close_sk_file:
#endif
	filp_close(sk, NULL);
close_skl_file:
	filp_close(sk_loader, NULL);
free_mem:
	vunmap(vsm_skm_va);
	vsm_skm_pa = 0;
	return ret;
}
