#include <stdio.h>
#include <stdlib.h>
#include "maple_tree.h"
#include "../makedumpfile.h"
#include "../btf_info.h"
#include "../kallsyms.h"
#include "../extension.h"

/*
 * These syms/types are must-have for the extension.
*/
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

struct ft_page_info {
	unsigned long pfn;
	unsigned long num;
	struct ft_page_info *next;
};

static struct ft_page_info *ft_head_discard = NULL;

static void update_filter_pages_info(unsigned long pfn, unsigned long num)
{
	struct ft_page_info *p, **ft_head;
	struct ft_page_info *new_p = malloc(sizeof(struct ft_page_info));

	ft_head = &ft_head_discard;

	if (!new_p) {
		fprintf(stderr, "%s: Can't allocate memory for ft_page_info\n",
			__func__);
		return;
	}
	new_p->pfn = pfn;
	new_p->num = num;
	new_p->next = NULL;

	if (!(*ft_head) || (*ft_head)->pfn > new_p->pfn) {
		new_p->next = (*ft_head);
		(*ft_head) = new_p;
		return;
	}

	p = (*ft_head);
	while (p->next != NULL && p->next->pfn < new_p->pfn) {
		p = p->next;
	}

	new_p->next = p->next;
	p->next = new_p;
}

static int filter_page(unsigned long pfn, struct ft_page_info **p)
{
	struct ft_page_info *ft_head = ft_head_discard;

	if (ft_head == NULL)
		return PG_UNDECID;

	if (*p == NULL)
		*p = ft_head;

	/* The gap before 1st block */
	if (pfn >= 0 && pfn < ft_head->pfn)
		return PG_UNDECID;

	/* Handle 1~(n-1) blocks and following gaps */
	while ((*p)->next) {
		if (pfn >= (*p)->pfn && pfn < (*p)->pfn + (*p)->num)
			return PG_EXCLUDE; // hit the block
		if (pfn >= (*p)->pfn + (*p)->num && pfn < (*p)->next->pfn)
			return PG_UNDECID; // the gap after the block
		*p = (*p)->next;
	}

	/* The last block and gap */
	if (pfn >= (*p)->pfn + (*p)->num)
		return PG_UNDECID;
	else
		return PG_EXCLUDE;
}

static void do_cleanup(struct ft_page_info **ft_head)
{
	struct ft_page_info *p, *p_tmp;

	for (p = *ft_head; p;) {
		p_tmp = p;
		p = p->next;
		free(p_tmp);
	}
	*ft_head = NULL;
}

#define KERN_MEMBER_OFF(S, M) \
	GET_KERN_STRUCT_MEMBER_MOFF(S, M) / 8
#define MOD_MEMBER_OFF(MOD, S, M) \
	GET_MOD_STRUCT_MEMBER_MOFF(MOD, S, M) / 8

static void gather_amdgpu_mm_range_info(void)
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
					update_filter_pages_info(pfn, num_pages);
				}
			}
		}

		free(array_out);
		list = next_list(list);
	} while (list != init_task + KERN_MEMBER_OFF(task_struct, tasks));

	return;
}

/* Extension callback when makedumpfile do page filtering */
int extension_callback(unsigned long pfn, const void *pcache)
{
	struct ft_page_info *cur = NULL;

	return filter_page(pfn, &cur);
}

/* Entry of extension */
void extension_init(void)
{
	if (!maple_init()) {
		goto out;
	}
	gather_amdgpu_mm_range_info();
out:
	return;
}

__attribute__((destructor))
void extension_cleanup(void)
{
	do_cleanup(&ft_head_discard);
}
