#include <stdio.h>
#include "maple_tree.h"
#include "../makedumpfile.h"
#include "../btf_info.h"
#include "../kallsyms.h"
#include "../erase_info.h"

INIT_KERN_STRUCT_MEMBER(task_struct, tasks);
INIT_KERN_STRUCT_MEMBER(task_struct, mm);
INIT_KERN_STRUCT_MEMBER(mm_struct, mm_mt);
INIT_KERN_STRUCT_MEMBER(vm_area_struct, vm_ops);
INIT_KERN_STRUCT_MEMBER(vm_area_struct, vm_private_data);
INIT_MOD_STRUCT_MEMBER(amdgpu, ttm_buffer_object, ttm);
INIT_MOD_STRUCT_MEMBER(amdgpu, ttm_tt, pages);
INIT_MOD_STRUCT_MEMBER(amdgpu, ttm_tt, num_pages);
INIT_KERN_STRUCT(page);

INIT_KERN_SYM(init_task);
INIT_KERN_SYM(vmemmap_base);
INIT_MOD_SYM(amdgpu, amdgpu_gem_vm_ops);

#define KERN_MEMBER_OFF(S, M) \
	GET_KERN_STRUCT_MEMBER_MOFF(S, M) / 8
#define MOD_MEMBER_OFF(MOD, S, M) \
	GET_MOD_STRUCT_MEMBER_MOFF(MOD, S, M) / 8

static void do_filter(void)
{
	uint64_t init_task, list, list_offset, amdgpu_gem_vm_ops;
	uint64_t mm, vm_ops, tbo, ttm, num_pages, pages, pfn, vmemmap_base;
	int array_len;
	unsigned long *array_out;
	init_task = GET_KERN_SYM(init_task);
	amdgpu_gem_vm_ops = GET_MOD_SYM(amdgpu, amdgpu_gem_vm_ops);

	list = init_task + KERN_MEMBER_OFF(task_struct, tasks);

	do {
		readmem(VADDR, list - KERN_MEMBER_OFF(task_struct, tasks) + 
				KERN_MEMBER_OFF(task_struct, mm),
			&mm, sizeof(uint64_t));
		if (!mm) {
			list = next_list(list);
			continue;
		}

		array_out = mt_dump(mm + KERN_MEMBER_OFF(mm_struct, mm_mt), &array_len);
		if (!array_out)
			return;

		for (int i = 0; i < array_len; i++) {
			num_pages = 0;
			readmem(VADDR, array_out[i] + KERN_MEMBER_OFF(vm_area_struct, vm_ops),
				&vm_ops, GET_KERN_STRUCT_MEMBER_MSIZE(vm_area_struct, vm_ops));
			if (vm_ops == amdgpu_gem_vm_ops) {
				readmem(VADDR, array_out[i] +
					KERN_MEMBER_OFF(vm_area_struct, vm_private_data),
					&tbo, GET_KERN_STRUCT_MEMBER_MSIZE(vm_area_struct, vm_private_data));
				readmem(VADDR, tbo + MOD_MEMBER_OFF(amdgpu, ttm_buffer_object, ttm),
					&ttm, GET_MOD_STRUCT_MEMBER_MSIZE(amdgpu, ttm_buffer_object, ttm));
				if (ttm) {
					readmem(VADDR, ttm + MOD_MEMBER_OFF(amdgpu, ttm_tt, num_pages),
						&num_pages, GET_MOD_STRUCT_MEMBER_MSIZE(amdgpu, ttm_tt, num_pages));
					readmem(VADDR, ttm + MOD_MEMBER_OFF(amdgpu, ttm_tt, pages),
						&pages, GET_MOD_STRUCT_MEMBER_MSIZE(amdgpu, ttm_tt, pages));
					readmem(VADDR, pages, &pages, sizeof(unsigned long));
					readmem(VADDR, GET_KERN_SYM(vmemmap_base),
						&vmemmap_base, sizeof(unsigned long));
					pfn = (pages - vmemmap_base) / GET_KERN_STRUCT_SSIZE(page);
					update_filter_pages_info(pfn, num_pages, true);
				}
			}
		}

		free(array_out);
		list = next_list(list);
	} while (list != init_task + KERN_MEMBER_OFF(task_struct, tasks));

	return;
}

/* Entry of extension */
void entry(void)
{
	if (!maple_init()) {
		goto out;
	}
	do_filter();
out:
	return;
}