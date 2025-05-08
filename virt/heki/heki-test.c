// SPDX-License-Identifier: GPL-2.0-only
/*
 * Hypervisor Enforced Kernel Integrity (Heki) - Tests
 *
 * Copyright © 2023-2024 Microsoft Corporation
 */

#include <asm/asm.h>
#include <asm/special_insns.h>
#include <asm/desc.h>
#include <kunit/test.h>
#include <linux/processor.h>
#include <linux/heki.h>
#include <linux/set_memory.h>

#define HEKI_KUNIT_SUITE(suite_name) \
	static struct kunit_case suite_name##_test_cases[] = { \
		KUNIT_CASE(test_##suite_name), \
		{} \
	}; \
	static struct kunit_suite suite_name##_suite = { \
		.name = #suite_name, \
		.test_cases = suite_name##_test_cases, \
	};

gate_desc hacked_idt_table[IDT_ENTRIES] __page_aligned_bss;
struct desc_ptr hacked_idt;
gate_desc hacked_gdt_table[GDT_ENTRIES] __page_aligned_bss;
struct desc_ptr hacked_gdt;
gate_desc hacked_ldt_table[LDT_ENTRIES] __page_aligned_bss;
struct desc_ptr hacked_ldt;

/* Takes two pages to not change permission of other read-only pages. */
const char heki_test_const_buf[PAGE_SIZE * 2] = {};
long test_heki_exec_data(long);
void _test_exec_data_end(void);

/* Used to test ROP execution against the .rodata section. */
/* clang-format off */
asm(
".pushsection .rodata;" // NOT .text section
".global test_heki_exec_data;"
".type test_heki_exec_data, @function;"
"test_heki_exec_data:"
ASM_ENDBR
"movq %rdi, %rax;"
"inc %rax;"
ASM_RET
".size test_heki_exec_data, .-test_heki_exec_data;"
"_test_exec_data_end:"
".popsection");
/* clang-format on */

/* Returns true on error (i.e. GP fault), false otherwise. */
static __always_inline bool set_cr4(unsigned long value)
{
	int err = 0;

	might_sleep();
	/* clang-format off */
	asm volatile("1: mov %0,%%cr4\n"
		     "2:\n"
		     _ASM_EXTABLE_TYPE_REG(1b, 2b, EX_TYPE_ONE_REG, %1)
		     : "+r"(value), "+r"(err)
		     :);
	/* clang-format on */
	return err;
}

/* Control register pinning tests with SMEP check. */
static void test_heki_x86_cr_disable_smep(struct kunit *const test)
{
	/* SMEP should be initially enabled. */
	KUNIT_ASSERT_TRUE(test, __read_cr4() & X86_CR4_SMEP);

	/*
	 * Trying to disable SMEP, bypassing kernel self-protection by not
	 * using cr4_clear_bits(X86_CR4_SMEP), and checking GP fault.
	 */
	KUNIT_EXPECT_TRUE(test, set_cr4(__read_cr4() & ~X86_CR4_SMEP));

	/* SMEP should still be enabled. */
	KUNIT_EXPECT_TRUE(test, __read_cr4() & X86_CR4_SMEP);

	/* Re-enabling SMEP doesn't throw a GP fault. */
	KUNIT_EXPECT_FALSE(test, set_cr4(__read_cr4() | X86_CR4_SMEP));
	KUNIT_EXPECT_TRUE(test, __read_cr4() & X86_CR4_SMEP);
}

/* Returns true on error (i.e. GP fault), false otherwise. */
static __always_inline bool set_cr0(unsigned long value)
{
	int err = 0;

	might_sleep();
	/* clang-format off */
	asm volatile("1: mov %0,%%cr0\n"
		     "2:\n"
		     _ASM_EXTABLE_TYPE_REG(1b, 2b, EX_TYPE_ONE_REG, %1)
		     : "+r"(value), "+r"(err)
		     :);
	/* clang-format on */
	return err;
}

/* Control register pinning tests with SMEP check. */
static void test_heki_x86_cr_disable_wp(struct kunit *const test)
{
	/* SMEP should be initially enabled. */
	KUNIT_ASSERT_TRUE(test, read_cr0() & X86_CR0_WP);

	/* Trying to disable WP and checking GP fault. */
	KUNIT_EXPECT_TRUE(test, set_cr0(read_cr0() & ~X86_CR0_WP));

	/* WP should still be enabled. */
	KUNIT_EXPECT_TRUE(test, read_cr0() & X86_CR0_WP);

	/* Re-enabling SMEP doesn't throw a GP fault. */
	KUNIT_EXPECT_FALSE(test, set_cr0(read_cr0() | X86_CR0_WP));
	KUNIT_EXPECT_TRUE(test, read_cr0() & X86_CR0_WP);
}

static void test_heki_x86_idtr_hack(struct kunit *test)
{
	struct desc_ptr cur_idt, new_idt;

	store_idt(&cur_idt);
	memcpy(hacked_idt_table, (u8 *)cur_idt.address, cur_idt.size);
	hacked_idt.size = cur_idt.size;
	hacked_idt.address = (unsigned long)hacked_idt_table;

	load_idt(&hacked_idt);
	store_idt(&new_idt);

	KUNIT_EXPECT_EQ(test, cur_idt.address, new_idt.address);

	if (cur_idt.address != new_idt.address)
		load_idt(&cur_idt);

}

#ifndef CONFIG_PARAVIRT_XXL
static void test_heki_x86_gdtr_hack(struct kunit *test)
{
	struct desc_ptr cur_gdt, new_gdt;

	store_gdt(&cur_gdt);
	memcpy(hacked_gdt_table, (u8 *)cur_gdt.address, cur_gdt.size);
	hacked_gdt.size = cur_gdt.size;
	hacked_gdt.address = (unsigned long)hacked_gdt_table;

	load_gdt(&hacked_gdt);
	store_gdt(&new_gdt);

	KUNIT_EXPECT_EQ(test, cur_gdt.address, new_gdt.address);

	if (cur_gdt.address != new_gdt.address)
		load_gdt(&cur_gdt);
}

static void test_heki_x86_ldtr_hack(struct kunit *test)
{
	struct desc_ptr cur_ldt, new_ldt;

	store_ldt(cur_ldt);
	memcpy(hacked_ldt_table, (u8 *)cur_ldt.address, cur_ldt.size);
	hacked_ldt.size = cur_ldt.size;
	hacked_ldt.address = (unsigned long)hacked_ldt_table;

	load_ldt(hacked_ldt);
	store_ldt(new_ldt);

	KUNIT_EXPECT_EQ(test, cur_ldt.address, new_ldt.address);

	if (cur_ldt.address != new_ldt.address)
		load_ldt(cur_ldt);
}

static void test_heki_x86_tr_hack(struct kunit *test)
{
	unsigned long cur_tr, hacked_tr = 0x1234, new_tr;

	store_tr(cur_tr);
	load_tr(hacked_tr);
	store_tr(new_tr);

	KUNIT_EXPECT_EQ(test, cur_tr, new_tr);

	if (cur_tr != new_tr)
		load_tr(cur_tr);
}
#endif /* CONFIG_PARAVIRT_XXL */

static void test_heki_x86_lstar_hack(struct kunit *test)
{
	unsigned long long cur_lstar, new_lstar;

	rdmsrl(MSR_LSTAR, cur_lstar);
	wrmsrl(MSR_LSTAR, 0x1234);
	rdmsrl(MSR_LSTAR, new_lstar);

	KUNIT_EXPECT_EQ(test, cur_lstar, new_lstar);
	if (cur_lstar != new_lstar)
		wrmsrl(MSR_LSTAR, cur_lstar);
}

static void test_heki_x86_star_hack(struct kunit *test)
{
	unsigned long long cur_star, new_star;

	rdmsrl(MSR_STAR, cur_star);
	wrmsrl(MSR_STAR, 0x1234);
	rdmsrl(MSR_STAR, new_star);

	KUNIT_EXPECT_EQ(test, cur_star, new_star);
	if (cur_star != new_star)
		wrmsrl(MSR_STAR, cur_star);
}

static void test_heki_x86_cstar_hack(struct kunit *test)
{
	unsigned long long cur_cstar, new_cstar;

	rdmsrl(MSR_CSTAR, cur_cstar);
	wrmsrl(MSR_CSTAR, 0x1234);
	rdmsrl(MSR_CSTAR, new_cstar);

	KUNIT_EXPECT_EQ(test, cur_cstar, new_cstar);
	if (cur_cstar != new_cstar)
		wrmsrl(MSR_CSTAR, cur_cstar);
}

static void test_heki_x86_efer_hack(struct kunit *test)
{
	unsigned long long cur_efer, new_efer;

	rdmsrl(MSR_EFER, cur_efer);
	wrmsrl(MSR_EFER, 0x1234);
	rdmsrl(MSR_EFER, new_efer);

	KUNIT_EXPECT_EQ(test, cur_efer, new_efer);
	if (cur_efer != new_efer)
		wrmsrl(MSR_EFER, cur_efer);
}

static void test_heki_x86_apic_base_hack(struct kunit *test)
{
	unsigned long long cur_apic_base, new_apic_base;

	rdmsrl(MSR_IA32_APICBASE, cur_apic_base);
	wrmsrl(MSR_IA32_APICBASE, 0x1234);
	rdmsrl(MSR_IA32_APICBASE, new_apic_base);

	KUNIT_EXPECT_EQ(test, cur_apic_base, new_apic_base);
	if (cur_apic_base != new_apic_base)
		wrmsrl(MSR_IA32_APICBASE, cur_apic_base);
}

static void test_heki_x86_sysenter_cs_hack(struct kunit *test)
{
	unsigned long long cur_sysenter_cs, new_sysenter_cs;

	rdmsrl(MSR_IA32_SYSENTER_CS, cur_sysenter_cs);
	wrmsrl(MSR_IA32_SYSENTER_CS, 0x1234);
	rdmsrl(MSR_IA32_SYSENTER_CS, new_sysenter_cs);

	KUNIT_EXPECT_EQ(test, cur_sysenter_cs, new_sysenter_cs);
	if (cur_sysenter_cs != new_sysenter_cs)
		wrmsrl(MSR_IA32_SYSENTER_CS, cur_sysenter_cs);
}

static void test_heki_x86_sysenter_eip_hack(struct kunit *test)
{
	unsigned long long cur_sysenter_eip, new_sysenter_eip;

	rdmsrl(MSR_IA32_SYSENTER_EIP, cur_sysenter_eip);
	wrmsrl(MSR_IA32_SYSENTER_EIP, 0x1234);
	rdmsrl(MSR_IA32_SYSENTER_EIP, new_sysenter_eip);

	KUNIT_EXPECT_EQ(test, cur_sysenter_eip, new_sysenter_eip);
	if (cur_sysenter_eip != new_sysenter_eip)
		wrmsrl(MSR_IA32_SYSENTER_EIP, cur_sysenter_eip);
}

static void test_heki_x86_sysenter_esp_hack(struct kunit *test)
{
	unsigned long long cur_sysenter_esp, new_sysenter_esp;

	rdmsrl(MSR_IA32_SYSENTER_ESP, cur_sysenter_esp);
	wrmsrl(MSR_IA32_SYSENTER_ESP, 0x1234);
	rdmsrl(MSR_IA32_SYSENTER_ESP, new_sysenter_esp);

	KUNIT_EXPECT_EQ(test, cur_sysenter_esp, new_sysenter_esp);
	if (cur_sysenter_esp != new_sysenter_esp)
		wrmsrl(MSR_IA32_SYSENTER_ESP, cur_sysenter_esp);
}

static void test_heki_x86_sfmask_hack(struct kunit *test)
{
	unsigned long long cur_sfmask, new_sfmask;

	rdmsrl(MSR_SYSCALL_MASK, cur_sfmask);
	wrmsrl(MSR_SYSCALL_MASK, 0x1234);
	rdmsrl(MSR_SYSCALL_MASK, new_sfmask);

	KUNIT_EXPECT_EQ(test, cur_sfmask, new_sfmask);
	if (cur_sfmask != new_sfmask)
		wrmsrl(MSR_SYSCALL_MASK, cur_sfmask);
}

static void test_heki_x86_write_to_const(struct kunit *test)
{
	char *const ro_buf = heki_test_const_buf;

	KUNIT_EXPECT_EQ(test, 0, *ro_buf);

	kunit_warn(
		test,
		"Bypassing kernel self-protection: mark memory as writable\n");
	/*
	 * Removes execute permission that might be set by bugdoor-exec,
	 * because change_page_attr_clear() is not use by set_memory_rw().
	 * This is required since commit 652c5bf380ad ("x86/mm: Refuse W^X
	 * violations").
	 */
	KUNIT_ASSERT_FALSE(test, set_memory_nx((unsigned long)PTR_ALIGN_DOWN(
						       ro_buf, PAGE_SIZE),
					       1));
	KUNIT_ASSERT_FALSE(test, set_memory_rw((unsigned long)PTR_ALIGN_DOWN(
						       ro_buf, PAGE_SIZE),
					       1));

	kunit_warn(test, "Trying memory write\n");
	*ro_buf = 0x11;
	KUNIT_EXPECT_EQ(test, 0, *ro_buf);
	kunit_warn(test, "New content: 0x%02x\n", *ro_buf);
}

typedef long test_exec_t(long);

static void test_heki_x86_exec(struct kunit *test)
{
	const size_t exec_size = 7;
	unsigned long nx_page_start = (unsigned long)PTR_ALIGN_DOWN(
		(const void *const)test_heki_exec_data, PAGE_SIZE);
	unsigned long nx_page_end = (unsigned long)PTR_ALIGN(
		(const void *const)test_heki_exec_data + exec_size, PAGE_SIZE);
	test_exec_t *exec = (test_exec_t *)test_heki_exec_data;
	long ret;

	kunit_warn(
		test,
		"Bypassing kernel-self protection: mark memory as executable\n");
	KUNIT_ASSERT_FALSE(test,
			   set_memory_rox(nx_page_start,
					  PFN_UP(nx_page_end - nx_page_start)));

	kunit_warn(
		test,
		"Trying to execute data (ROP) in (initially) non-executable memory\n");
	ret = exec(3);

	/* This should not be reached because of the uncaught page fault. */
	KUNIT_EXPECT_EQ(test, 3, ret);
	kunit_warn(test, "Result of execution: 3 + 1 = %ld\n", ret);
}

HEKI_KUNIT_SUITE(heki_x86_cr_disable_smep);
HEKI_KUNIT_SUITE(heki_x86_cr_disable_wp);
HEKI_KUNIT_SUITE(heki_x86_idtr_hack);
#ifndef CONFIG_PARAVIRT_XXL
HEKI_KUNIT_SUITE(heki_x86_gdtr_hack);
HEKI_KUNIT_SUITE(heki_x86_ldtr_hack);
HEKI_KUNIT_SUITE(heki_x86_tr_hack);
#endif
HEKI_KUNIT_SUITE(heki_x86_lstar_hack);
HEKI_KUNIT_SUITE(heki_x86_star_hack);
HEKI_KUNIT_SUITE(heki_x86_cstar_hack);
HEKI_KUNIT_SUITE(heki_x86_efer_hack);
HEKI_KUNIT_SUITE(heki_x86_apic_base_hack);
HEKI_KUNIT_SUITE(heki_x86_sysenter_cs_hack);
HEKI_KUNIT_SUITE(heki_x86_sysenter_eip_hack);
HEKI_KUNIT_SUITE(heki_x86_sysenter_esp_hack);
HEKI_KUNIT_SUITE(heki_x86_sfmask_hack);
HEKI_KUNIT_SUITE(heki_x86_write_to_const);
HEKI_KUNIT_SUITE(heki_x86_exec);

kunit_test_suites(
	&heki_x86_cr_disable_smep_suite,
	&heki_x86_cr_disable_wp_suite,
	&heki_x86_idtr_hack_suite,
#ifndef CONFIG_PARAVIRT_XXL
	&heki_x86_gdtr_hack_suite,
	&heki_x86_ldtr_hack_suite,
	&heki_x86_tr_hack_suite,
#endif
	&heki_x86_lstar_hack_suite,
	&heki_x86_star_hack_suite,
	&heki_x86_cstar_hack_suite,
	&heki_x86_efer_hack_suite,
	&heki_x86_apic_base_hack_suite,
	&heki_x86_sysenter_cs_hack_suite,
	&heki_x86_sysenter_eip_hack_suite,
	&heki_x86_sysenter_esp_hack_suite,
	&heki_x86_sfmask_hack_suite,
	&heki_x86_write_to_const_suite,
	&heki_x86_exec_suite
);

MODULE_IMPORT_NS(HEKI_KUNIT_TEST);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Tests for Hypervisor Enforced Kernel Integrity (Heki)");
