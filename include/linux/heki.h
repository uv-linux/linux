/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Hypervisor Enforced Kernel Integrity (Heki) - Definitions
 *
 * Copyright © 2023 Microsoft Corporation
 */

#ifndef __HEKI_H__
#define __HEKI_H__

#include <linux/types.h>
#include <linux/bug.h>
#include <linux/cache.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/printk.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/vmalloc.h>
#include <linux/xarray.h>

struct load_info;

#include <asm/heki.h>

#include <asm/heki.h>

/*
 * This structure contains a guest physical range and its attributes (e.g.,
 * permissions (RWX)).
 */
struct heki_range {
	unsigned long va;
	phys_addr_t pa;
	phys_addr_t epa;
	unsigned long attributes;
};

/*
 * Guest ranges are passed to the VMM or hypervisor so they can be authenticated
 * and their permissions can be set in the host page table. When an array of
 * these is passed to the Hypervisor or VMM, the array must be in physically
 * contiguous memory.
 *
 * This struct occupies one page. In each page, an array of guest ranges can
 * be passed. A guest request to the VMM/Hypervisor may contain a list of
 * these structs (linked by "next_pa").
 */
struct heki_page {
	struct heki_page *next;
	phys_addr_t next_pa;
	unsigned long nranges;
	struct heki_range ranges[];
};

enum heki_kdata_type {
	HEKI_SYSTEM_CERTS,
	HEKI_REVOCATION_CERTS,
	HEKI_BLACKLIST_HASHES,
	HEKI_KERNEL_INFO,
	HEKI_KERNEL_DATA,
	HEKI_KDATA_MAX,
};

/*
 * Attribute value for module info that does not conflict with any of the
 * values in enum mod_mem_type.
 */
#define MOD_ELF		MOD_MEM_NUM_TYPES

#define HEKI_MODULE_RESERVE_SIZE	0x40000000UL

/* We store the hash, the prefix which is either "tbs:" or "bin:", and the null terminator */
#define HEKI_MAX_TOTAL_HASH_LEN 133

/*
 * According to crypto/asymmetric_keys/x509_cert_parser.c:x509_note_pkey_algo(),
 * the size of the currently longest supported hash algorithm is 512 bits,
 * which translates into 128 hex characters.
 */
#define MAX_HASH_LEN	128

struct heki_kinfo {
	struct kernel_symbol	*ksymtab_start;
	struct kernel_symbol	*ksymtab_end;
	struct kernel_symbol	*ksymtab_gpl_start;
	struct kernel_symbol	*ksymtab_gpl_end;
	struct heki_arch_kinfo	arch;
};

/*
 * A hypervisor that supports Heki will instantiate this structure to
 * provide hypervisor specific functions for Heki.
 */
struct heki_hypervisor {
	/* Lock control registers. */
	int (*lock_crs)(void);

	/* Signal end of kernel boot */
	int (*finish_boot)(void);

	/* Protect guest memory */
	int (*protect_memory)(phys_addr_t pa, unsigned long nranges);

	/* Load kernel data */
	int (*load_kdata)(phys_addr_t pa, unsigned long nranges);

	/*
	 * Pass a module blob (ELF file) and module contents to KVM for
	 * validation.
	 */
	long (*validate_module)(phys_addr_t pa, unsigned long nranges,
				unsigned long flags);

	/* Free module init sections. */
	int (*free_module_init)(long token);

	/* Unload module. */
	int (*unload_module)(long token);

	/* Copy secondary key data. */
	int (*copy_secondary_key)(phys_addr_t pa, unsigned long npages);
};

/*
 * The ranges contain VTL0 pages. VTL0 pages are mapped into VTL1 address space
 * so VTL1 can access VTL0 memory at va.
 *
 * Each module section (text, data, etc) is represented by a heki_mem. Module
 * sections are reconstructed in VTL1 and compared with the corresponding
 * VTL0 sections. Reconstruction involves module symbol resolution and module
 * relocation. These steps involve symbol addresses. To make the reconstruction
 * simpler, we map the VTL1 module sections at the same virtual addresses as
 * their corresponding sections in VTL0. We call this identity mapping. This
 * keeps the addresses the same in VTL0 and VTL1. A VTL1 section is accessed
 * at ranges->va since that is the starting va for the section.
 */
struct heki_mem {
	void			*va;
	unsigned long		size;
	long			offset;
	struct heki_range	*ranges;
	unsigned long		nranges;
	struct page		**pages;
	bool			retain;
};

/* This is created for each guest module in the host. */
struct heki_mod {
	struct list_head node;
	struct heki_range *ranges;
	char name[MODULE_NAME_LEN];
	long token;
	struct heki_mem mem[MOD_ELF + 1];
	struct module *mod;
};

#ifdef CONFIG_HEKI

/* Currently 83 hashes get added to the blacklist keyring */
#define HEKI_MAX_TOTAL_HASHES 400

/*
 * If the active hypervisor supports Heki, it will plug its heki_hypervisor
 * pointer into this heki structure.
 */
struct heki {
	struct heki_hypervisor *hypervisor;
	struct mutex lock;
};

extern struct heki heki;
/*
 * The kernel page table is walked to locate kernel mappings. For each
 * mapping, a callback function is called. The table walker passes information
 * about the mapping to the callback using this structure.
 */
struct heki_args {
	/* Information passed by the table walker to the callback. */
	unsigned long va;
	phys_addr_t pa;
	size_t size;
	unsigned long flags;
	struct xarray permissions;

	/* attributes passed to heki_add_pa_range(). */
	unsigned long attributes;

	/* Page list is built by the callback. */
	struct heki_page *head;
	struct heki_page *tail;
	struct heki_range *cur;
	unsigned long nranges;
	phys_addr_t head_pa;
};

/* Callback function called by the table walker. */
typedef void (*heki_func_t)(struct heki_args *args);

void heki_late_init(void);
void heki_register_hypervisor(struct heki_hypervisor *hypervisor);
void heki_walk(unsigned long va, unsigned long va_end, heki_func_t func,
	       struct heki_args *args);
void heki_map(unsigned long va, unsigned long end);
void heki_init_perm(unsigned long va, unsigned long end,
		    struct heki_args *args);
void heki_protect(unsigned long va, unsigned long end, struct heki_args *args);
void heki_add_range(struct heki_args *args, unsigned long va,
		    phys_addr_t pa, phys_addr_t epa);
void heki_cleanup_args(struct heki_args *args);
void heki_load_kdata(void);
long heki_validate_module(struct module *mod, struct load_info *info, int flags);
void heki_free_module_init(struct module *mod);
void heki_unload_module(struct module *mod);
void heki_copy_secondary_key(const void *data, size_t size);
void heki_store_blacklist_raw_hashes(const char *hash);
void heki_get_ranges(struct heki_args *args);

/* Arch-specific functions. */
void heki_arch_init(void);
unsigned long heki_flags_to_permissions(unsigned long flags);
void heki_load_arch_kinfo(struct heki_kinfo *kinfo);

#else /* !CONFIG_HEKI */

static inline void heki_late_init(void)
{
}

static inline long heki_validate_module(struct module *mod,
					struct load_info *info, int flags)
{
	return 0;
}

static inline void heki_free_module_init(struct module *mod) { }
static inline void heki_unload_module(struct module *mod) { }
static inline void heki_copy_secondary_key(const void *data, size_t size) { }

static inline void heki_register_hypervisor(struct heki_hypervisor *hypervisor) { }

static inline void heki_store_blacklist_raw_hashes(const char *hash)
{
}

#endif /* CONFIG_HEKI */

#endif /* __HEKI_H__ */
