#include <stdbool.h>

#include "../extension.h"
#include "../makedumpfile.h"
#include "../btf_info.h"
#include "../kallsyms.h"
#include "maple_tree.h"
#include "vma_rbtree.h"

/* Required struct fields */
INIT_KERN_STRUCT_MEMBER(task_struct, tasks);
INIT_KERN_STRUCT_MEMBER(task_struct, signal);
INIT_KERN_STRUCT_MEMBER(task_struct, thread_node);
INIT_KERN_STRUCT_MEMBER(task_struct, stack);
INIT_KERN_STRUCT_MEMBER(task_struct, mm);
INIT_KERN_STRUCT_MEMBER(vm_area_struct, anon_vma);
INIT_KERN_STRUCT_MEMBER(vm_area_struct, vm_pgoff);
INIT_KERN_STRUCT_MEMBER(page, index);
INIT_KERN_STRUCT_MEMBER(signal_struct, thread_head);
INIT_KERN_STRUCT_MEMBER(list_head, next);
INIT_KERN_STRUCT_MEMBER(pt_regs, sp);
INIT_KERN_STRUCT(pt_regs);

/* Optional struct fields */
INIT_OPT_KERN_STRUCT_MEMBER(thread_union, stack);
INIT_OPT_KERN_STRUCT_MEMBER(mm_struct, mm_mt);
INIT_OPT_KERN_STRUCT_MEMBER(mm_struct, mm_rb);

/* Required symbols */
INIT_KERN_SYM(init_task);

/* Optional symbols */
INIT_OPT_KERN_SYM(fred_rsp0);
INIT_OPT_KERN_SYM(__start_init_stack);
INIT_OPT_KERN_SYM(__end_init_stack);
INIT_OPT_KERN_SYM(__start_init_task);
INIT_OPT_KERN_SYM(__end_init_task);

unsigned long THREAD_SIZE;
bool ready;

#define MEMBER_OFF(S, M) \
	(GET_KERN_STRUCT_MEMBER_MOFF(S, M) / 8)


static bool for_each_task(bool (*task_fn)(unsigned long))
{
	unsigned long curr_proc = GET_KERN_SYM(init_task);
	do {
		unsigned long signal;
		if (!readmem(VADDR, curr_proc + MEMBER_OFF(task_struct, signal),
			     &signal, sizeof(signal)))
			return false;

		unsigned long thread_head = signal + MEMBER_OFF(signal_struct, thread_head);
		unsigned long next;
		if (!readmem(VADDR, thread_head + MEMBER_OFF(list_head, next), &next, sizeof(next)))
			return false;

		while (next != thread_head) {
			unsigned long curr_thread = next - MEMBER_OFF(task_struct, thread_node);

			if (!task_fn(curr_thread))
				return false;

			if (!readmem(VADDR,
				     curr_thread + MEMBER_OFF(task_struct, thread_node) + MEMBER_OFF(list_head, next),
				     &next, sizeof(next)))
				return false;
		}

		if (!readmem(VADDR, curr_proc + MEMBER_OFF(task_struct, tasks) + MEMBER_OFF(list_head, next),
			     &next, sizeof(next)))
			return false;
		curr_proc = next - MEMBER_OFF(task_struct, tasks);

	} while (curr_proc != GET_KERN_SYM(init_task));

	return true;
}

static unsigned long task_sp(unsigned long taskp)
{
	// The stack pointer is stored on entry to the kernel at the top of the
	// kernel stack. If the task in on-cpu, the stack pointer will be in the
	// PRSTATUS, but the stale value is very likely to be useful enough.
	unsigned long user_sp_loc;
	if (!readmem(VADDR, taskp + MEMBER_OFF(task_struct, stack),
		     &user_sp_loc, sizeof(user_sp_loc)))
		return 0;

	user_sp_loc += THREAD_SIZE;
	user_sp_loc -= GET_KERN_STRUCT_SSIZE(pt_regs);
	if (KERN_SYM_EXIST(fred_rsp0))
		user_sp_loc -= 16;
	user_sp_loc += MEMBER_OFF(pt_regs, sp);

	unsigned long sp;
	if (!readmem(VADDR, user_sp_loc, &sp, sizeof(sp)))
		return 0;
	return sp;
}

struct task_stack {
	unsigned long anon_vma;
	unsigned long index_start;
	unsigned long index_end;
};

static struct task_stack *stacks;
static size_t stacks_count;
static size_t stacks_alloc;

static bool append_task_stack(struct task_stack *newstack)
{
	if (stacks_count == stacks_alloc) {
		if (stacks_alloc)
			stacks_alloc *= 2;
		else
			stacks_alloc = 512;
		struct task_stack *newarr = realloc(stacks, stacks_alloc * sizeof(stacks[0]));
		if (!newarr) {
			return false;
		}
		stacks = newarr;
	}
	stacks[stacks_count++] = *newstack;
	return true;
}

static bool record_task_stack(unsigned long taskp)
{
	// Tasks with NULL mm are either exiting or kthreads, neither of which
	// will have useful user stack pointers.
	unsigned long task_mm;
	if (!readmem(VADDR, taskp + MEMBER_OFF(task_struct, mm), &task_mm, sizeof(task_mm))
	    || !task_mm)
		return true;

	unsigned long sp = task_sp(taskp);
	if (!sp)
		return true;

	unsigned long vma = 0;
	if (KERN_STRUCT_MEMBER_EXIST(mm_struct, mm_mt))
		vma = find_vma_mtree(task_mm + MEMBER_OFF(mm_struct, mm_mt), sp);
	else if (KERN_STRUCT_MEMBER_EXIST(mm_struct, mm_rb))
		vma = find_vma_rbtree(task_mm + MEMBER_OFF(mm_struct, mm_rb), sp);
	if (!vma)
		return true;

	unsigned long vm_start, vm_end, anon_vma, vm_pgoff;
	if (!readmem(VADDR, vma + MEMBER_OFF(vm_area_struct, anon_vma), &anon_vma, sizeof(anon_vma)) ||
	    !anon_vma ||
	    !readmem(VADDR, vma + MEMBER_OFF(vm_area_struct, vm_start), &vm_start, sizeof(vm_start)) ||
	    !readmem(VADDR, vma + MEMBER_OFF(vm_area_struct, vm_end), &vm_end, sizeof(vm_end)) ||
	    !readmem(VADDR, vma + MEMBER_OFF(vm_area_struct, vm_pgoff), &vm_pgoff, sizeof(vm_pgoff)))
		return true;

	// Construct a range of indices we would like to retain. This is the
	// range of stack pages starting with the stack pointer, and continuing
	// to the top of the stack vma, or until a limit of 128 pages per task
	// is reached.
	unsigned long pgoff_start = (sp - vm_start) >> PAGESHIFT();
	pgoff_start += vm_pgoff;
	unsigned long pgoff_end = (vm_end - vm_start) >> PAGESHIFT();
	pgoff_end += vm_pgoff;
	if (pgoff_start + 128 < pgoff_end)
		pgoff_end = pgoff_start + 128;

	struct task_stack stack = {anon_vma | 1, pgoff_start, pgoff_end};
	if (!append_task_stack(&stack))
		return false;

	return true;
}

static int stack_compar(const void *lhs, const void *rhs)
{
	const struct task_stack *lhss = lhs, *rhss = rhs;
	if (lhss->anon_vma < rhss->anon_vma)
		return -1;
	else if (lhss->anon_vma > rhss->anon_vma)
		return 1;
	else
		return 0;
}

void extension_init(void)
{
	if (KERN_STRUCT_MEMBER_EXIST(mm_struct, mm_mt)) {
		if (!maple_init())
			return;
	} else if (KERN_STRUCT_MEMBER_EXIST(mm_struct, mm_rb)) {
		if (!vma_rbtree_init())
			return;
	} else {
		ERRMSG("error: Neither mtree nor rbtree available for VMA walking\n");
		return;
	}
	if (!KERN_STRUCT_EXIST(pt_regs)) {
		ERRMSG("error: missing pt_regs incfo\n");
		return;
	}
	if (!KERN_SYM_EXIST(init_task)) {
		ERRMSG("error: missing init_task symbol\n");
		return;
	}

	// Determine THREAD_SIZE, which is necessary to find the offset of the
	// userspace stack pointer register from the kernel thread stack.
	//
	// - Prior to v4.16, 0500871f21b23 ("Construct init thread stack in the
	//   linker script rather than by union"), it was found in thread_union.
	// - Between v4.16 and v6.10, 8f69cba096b5c ("x86: Rename
	//   __{start,end}_init_task to __{start,end}_init_stack"), the stack
	//   size can be inferred by the __{start,end}_init_task symbols.
	// - Since v6.10, the size is inferred by __{start,end}_init_stack.
	if (KERN_STRUCT_MEMBER_EXIST(thread_union, stack)) {
		THREAD_SIZE = GET_KERN_STRUCT_MEMBER_MSIZE(thread_union, stack);
	} else if (KERN_SYM_EXIST(__start_init_stack) &&
		   KERN_SYM_EXIST(__end_init_stack) &&
		   GET_KERN_SYM(__end_init_stack) > GET_KERN_SYM(__start_init_stack)) {
		THREAD_SIZE = GET_KERN_SYM(__end_init_stack) - GET_KERN_SYM(__start_init_stack);
	} else if (KERN_SYM_EXIST(__start_init_task) &&
		   KERN_SYM_EXIST(__end_init_task) &&
		   GET_KERN_SYM(__end_init_task) > GET_KERN_SYM(__start_init_task)) {
		THREAD_SIZE = GET_KERN_SYM(__end_init_task) - GET_KERN_SYM(__start_init_task);
	} else {
		ERRMSG("Could not determine THREAD_SIZE: neither __start_init_stack "
		       "nor __start_init_task found in kallsyms, nor is thread_union "
		       "found in BTF.\n");
		return;
	}
	fprintf(stderr, "THREAD_SIZE: %lu\n", THREAD_SIZE);

	for_each_task(&record_task_stack);
	struct task_stack *tmp = realloc(stacks, stacks_count * sizeof(*tmp));
	if (tmp) {
		stacks = tmp;
		stacks_alloc = stacks_count;
	}
	qsort(stacks, stacks_count, sizeof(*stacks), &stack_compar);
	ready = true;
}

static int count_retained;
static int count_checked;
static int count_cached;
int extension_callback(unsigned long pfn, const void *pcache)
{
	/* Do not bother if we failed to initialize */
	if (!ready)
		return PG_UNDECID;

	/* Only test anonymous pages */
	unsigned long mapping = ULONG(pcache + OFFSET(page.mapping));
	unsigned long flags = ULONG(pcache + OFFSET(page.flags));
	unsigned int _mapcount = 0;
	if (OFFSET(page._mapcount) != NOT_FOUND_STRUCTURE)
		_mapcount = UINT(pcache + OFFSET(page._mapcount));
	if (!isAnon(mapping, flags, _mapcount))
		return PG_UNDECID;

	/* Fetch the index field */
	unsigned long index = ULONG(pcache + MEMBER_OFF(page, index));

	static struct {
		unsigned long mapping;
		struct task_stack *result;
	} cache;

	if (!(mapping & 1))
		return PG_UNDECID;

	if (mapping != cache.mapping) {
		count_checked++;
		struct task_stack search = {mapping, 0, 0};
		struct task_stack *result = bsearch(&search, stacks, stacks_count,
						sizeof(search), &stack_compar);
		if (!result)
			return PG_UNDECID;

		cache.mapping = mapping;
		cache.result = result;

	} else {
		count_cached++;
	}

	bool res = index >= cache.result->index_start && index < cache.result->index_end;
	if (res) {
		count_retained++;
		return PG_INCLUDE;
	} else {
		return PG_UNDECID;
	}
}

__attribute__((destructor))
static void userstack_exit(void) {
	if (count_retained || count_checked || count_cached || stacks_count) {
		printf("Retained: %d searched: %d, cached: %d\n", count_retained, count_checked, count_cached);
		printf("Recorded %zu stack anon_vmas\n", stacks_count);
	}
}
