#include <stdint.h>

#include "common.h"
#include "makedumpfile.h"
#include "kallsyms_info.h"
#include "btf_info.h"


static struct {
	struct {
		int tasks;
		int signal;
		int thread_node;
		int stack;
		int mm;
	} task_struct;
	struct {
		int mm_mt;
		int mm_rb;
	} mm_struct;
	struct {
		int vm_start;
		int vm_end;
		int vm_rb;
		int anon_vma;
		int vm_pgoff;
	} vm_area_struct;
	struct {
		int sp;
	} pt_regs;
	struct {
		int thread_head;
	} signal_struct;
	struct {
		int next;
	} list_head;
	struct {
		int ma_root;
	} maple_tree;
	struct {
		int pivot;
		int slot;
		int meta;
	} maple_range_64;
	struct {
		int pivot;
		int slot;
		int meta;
	} maple_arange_64;
	struct {
		int end;
	} maple_metadata;
	struct {
		int rb_node;
	} rb_root;
	struct {
		int rb_left;
		int rb_right;
	} rb_node;
} OFF;

static struct {
	unsigned long long init_task;
	unsigned long long fred_rsp0;
	unsigned long long __start_init_stack;
	unsigned long long __end_init_stack;
	unsigned long long __start_init_task;
	unsigned long long __end_init_task;

	// Computed from the stack variables above, or from BTF.
	unsigned long long THREAD_SIZE;
} SYM;

static struct {
	int pt_regs;
	int maple_node;
	int thread_union__stack;
} SZ;

static int _load_sym_off(void)
{
#define _load_sym_or(x, or_what) \
	do { \
		SYM.x = kallsyms_lookup(#x); \
		if (!SYM.x) { \
			or_what; \
		} \
	} while (0)
#define _load_sym(x) _load_sym_or(x, ERRMSG("Could not find kallsyms symbol: \"%s\"\n", #x); return FALSE)
#define _load_opt_sym(x) _load_sym_or(x, SYM.x = 0)

	_load_sym(init_task);
	_load_opt_sym(fred_rsp0);
	_load_opt_sym(__start_init_stack);
	_load_opt_sym(__end_init_stack);
	_load_opt_sym(__start_init_task);
	_load_opt_sym(__end_init_task);
#undef _load_sym_or
#undef _load_sym
#undef _load_opt_sym

#define _load_off(x, y) \
	do { \
		OFF.x.y = btf_offset("struct "#x, #y); \
		if (OFF.x.y < 0) { \
			ERRMSG("Could not find btf structure offset: \"%s.%s\"\n", #x, #y); \
			return FALSE; \
		} \
	} while (0)
#define _load_opt_off(x, y) OFF.x.y = btf_offset("struct "#x, #y)
#define _load_sz(x, y) \
	do { \
		SZ.x = btf_sizeof(y); \
		if (SZ.x < 0) { \
			ERRMSG("Could not find btf structure size: \"%s\"\n", #x); \
			return FALSE; \
		} \
	} while (0)

	_load_off(task_struct, tasks);
	_load_off(task_struct, signal);
	_load_off(task_struct, thread_node);
	_load_off(task_struct, stack);
	_load_off(task_struct, mm);
	_load_off(vm_area_struct, vm_start);
	_load_off(vm_area_struct, vm_end);
	_load_off(vm_area_struct, anon_vma);
	_load_off(vm_area_struct, vm_pgoff);
	_load_off(signal_struct, thread_head);
	_load_off(list_head, next);
	_load_off(pt_regs, sp);

	// VMAs are stored in a maple tree starting in 524e00b36e8c ("mm: remove
	// rb tree.") from Linux 6.1. Prior they are stored in an rbtree.
	_load_opt_off(mm_struct, mm_mt);
	_load_opt_off(mm_struct, mm_rb);

	if (OFF.mm_struct.mm_mt >= 0) {
		_load_off(maple_tree, ma_root);
		_load_off(maple_range_64, pivot);
		_load_off(maple_range_64, slot);
		_load_off(maple_range_64, meta);
		_load_off(maple_arange_64, pivot);
		_load_off(maple_arange_64, slot);
		_load_off(maple_arange_64, meta);
		_load_off(maple_metadata, end);
		_load_sz(maple_node, "struct maple_node");
	} else if (OFF.mm_struct.mm_rb >= 0) {
		_load_off(vm_area_struct, vm_rb);
		_load_off(rb_root, rb_node);
		_load_off(rb_node, rb_left);
		_load_off(rb_node, rb_right);
	} else {
		ERRMSG("Loading VMAs requires either mtree or rbtree, neither found\n");
		return FALSE;
	}

	OFFSET(page.index) = btf_offset("struct page", "index");
	if (OFFSET(page.index) < 0) {
		ERRMSG("Could not find page structure offset: \"page.index\"\n");
		return FALSE;
	}

	_load_sz(pt_regs, "struct pt_regs");
	SZ.thread_union__stack = btf_member_sizeof("union thread_union", "stack");
#undef _load_off
#undef _load_opt_off
#undef _load_sz


	// Determine THREAD_SIZE, which is necessary to find the offset of the
	// userspace stack pointer register from the kernel thread stack.
	//
	// - Prior to v4.16, 0500871f21b23 ("Construct init thread stack in the
	//   linker script rather than by union"), it was found in thread_union.
	// - Between v4.16 and v6.10, 8f69cba096b5c ("x86: Rename
	//   __{start,end}_init_task to __{start,end}_init_stack"), the stack
	//   size can be inferred by the __{start,end}_init_task symbols.
	// - Since v6.10, the size is inferred by __{start,end}_init_stack.
	if (SZ.thread_union__stack > 0) {
		SYM.THREAD_SIZE = SZ.thread_union__stack;
	} else if (SYM.__start_init_stack && SYM.__end_init_stack &&
		   SYM.__end_init_stack > SYM.__start_init_stack) {
		SYM.THREAD_SIZE = SYM.__end_init_stack - SYM.__start_init_stack;
	} else if (SYM.__start_init_task && SYM.__end_init_task &&
		   SYM.__end_init_task > SYM.__start_init_task) {
		SYM.THREAD_SIZE = SYM.__end_init_task - SYM.__start_init_task;
	} else {
		ERRMSG("Could not determine THREAD_SIZE: neither __start_init_stack "
		       "nor __start_init_task found in kallsyms, nor is thread_union "
		       "found in BTF.\n");
		return FALSE;
	}

	return TRUE;
}

static int for_each_task(int (*task_fn)(unsigned long long))
{
	unsigned long long curr_proc = SYM.init_task;
	do {
		unsigned long long signal;
		if (!readmem(VADDR, curr_proc + OFF.task_struct.signal,
			     &signal, sizeof(signal)))
			return FALSE;

		unsigned long long thread_head = signal + OFF.signal_struct.thread_head;
		unsigned long long next;
		if (!readmem(VADDR, thread_head + OFF.list_head.next, &next, sizeof(next)))
			return FALSE;

		while (next != thread_head) {
			unsigned long long curr_thread = next - OFF.task_struct.thread_node;

			if (!task_fn(curr_thread))
				return FALSE;

			if (!readmem(VADDR,
				     curr_thread + OFF.task_struct.thread_node + OFF.list_head.next,
				     &next, sizeof(next)))
				return FALSE;
		}

		if (!readmem(VADDR, curr_proc + OFF.task_struct.tasks + OFF.list_head.next,
			     &next, sizeof(next)))
			return FALSE;
		curr_proc = next - OFF.task_struct.tasks;

	} while (curr_proc != SYM.init_task);

	return TRUE;
}

static unsigned long long task_sp(unsigned long long taskp)
{
	// The stack pointer is stored on entry to the kernel at the top of the
	// kernel stack. If the task in on-cpu, the stack pointer will be in the
	// PRSTATUS, but the stale value is very likely to be useful enough.
	unsigned long long user_sp_loc;
	if (!readmem(VADDR, taskp + OFF.task_struct.stack,
		     &user_sp_loc, sizeof(user_sp_loc)))
		return 0;

	user_sp_loc += SYM.THREAD_SIZE;
	user_sp_loc -= SZ.pt_regs;
	if (SYM.fred_rsp0)
		user_sp_loc -= 16;
	user_sp_loc += OFF.pt_regs.sp;

	unsigned long long sp;
	if (!readmem(VADDR, user_sp_loc, &sp, sizeof(sp)))
		return 0;
	return sp;
}

#define MAPLE_NODE_MASK 255UL
#define MAPLE_NODE_TYPE_MASK 0xF
#define MAPLE_NODE_TYPE_SHIFT 3

#define _XA_ZERO_ENTRY 1030
#define xa_is_node(x) (((x) & 3) == 2 && (x) > 4096)

static unsigned long long find_vma_mtree(unsigned long long mt, unsigned long long index)
{
	unsigned long long entry;

	if (!readmem(VADDR, mt + OFF.maple_tree.ma_root, &entry, sizeof(entry)))
		return 0;

	if (!xa_is_node(entry)) {
		if (index == 0)
			return entry;
		else
			return 0;
	}
	unsigned long long max = ULONGLONG_MAX;
	void *node = malloc(SZ.maple_node);
	if (!node)
		return 0;

	for (;;) {
		if (!readmem(VADDR, entry & ~MAPLE_NODE_MASK, node, SZ.maple_node)) {
			free(node);
			return 0;
		}

		int node_type = (entry >> MAPLE_NODE_TYPE_SHIFT) & MAPLE_NODE_TYPE_MASK;
		unsigned long long *pivot, *slot;
		uint8_t end;
		if (node_type == 3) {
			pivot = node + OFF.maple_arange_64.pivot;
			slot = node + OFF.maple_arange_64.slot;
			end = ((uint8_t *)node)[OFF.maple_arange_64.meta + OFF.maple_metadata.end];
		} else if (node_type == 1 || node_type == 2) {
			pivot = node + OFF.maple_range_64.pivot;
			slot = node + OFF.maple_range_64.slot;
			unsigned long long p = *(slot - 1);
			if (!p)
				end = ((uint8_t *)node)[OFF.maple_range_64.meta + OFF.maple_metadata.end];
			else {
				end = (slot - pivot) / sizeof(pivot);
				if (p == max)
					end--;
			}
		} else {
			ERRMSG("unrecognized maple node type: %d\n", node_type);
			free(node);
			return 0;
		}
		int offset = 0;
		for (offset = 0; offset < end; offset++) {
			if (pivot[offset] >= index) {
				max = pivot[offset];
				break;
			}
		}
		if (&pivot[offset] >= slot)
			offset = end;

		entry = slot[offset];
		if (node_type == 1) {
			// leaf:
			free(node);
			if (entry == _XA_ZERO_ENTRY)
				return 0;
			return entry;
		}
	}
}

unsigned long long find_vma_rbtree(unsigned long long rb_root, unsigned long long address)
{
	unsigned long long node, vma, vm_start, vm_end, rb_left, rb_right;
	if (!readmem(VADDR, rb_root, &node, sizeof(node)))
		return 0;


	while (node > OFF.vm_area_struct.vm_rb) {
		vma = node - OFF.vm_area_struct.vm_rb;
		if (!readmem(VADDR, vma + OFF.vm_area_struct.vm_start, &vm_start, sizeof(vm_start)) ||
		!readmem(VADDR, vma + OFF.vm_area_struct.vm_end, &vm_end, sizeof(vm_end)) ||
		!readmem(VADDR, node + OFF.rb_node.rb_left, &rb_left, sizeof(rb_left)) ||
		!readmem(VADDR, node + OFF.rb_node.rb_right, &rb_right, sizeof(rb_right)))
			return 0;

		if (address < vm_start)
			node = rb_left;
		else if (address >= vm_end)
			node = rb_right;
		else
			return vma;
	}
	return 0;
}

struct task_stack {
	unsigned long long anon_vma;
	unsigned long long index_start;
	unsigned long long index_end;
};

static struct task_stack *stacks;
static size_t stacks_count;
static size_t stacks_alloc;

static int append_task_stack(struct task_stack *newstack)
{
	if (stacks_count == stacks_alloc) {
		if (stacks_alloc)
			stacks_alloc *= 2;
		else
			stacks_alloc = 512;
		struct task_stack *newarr = realloc(stacks, stacks_alloc * sizeof(stacks[0]));
		if (!newarr) {
			return FALSE;
		}
		stacks = newarr;
	}
	stacks[stacks_count++] = *newstack;
	return TRUE;
}

static int record_task_stack(unsigned long long taskp)
{
	// Tasks with NULL mm are either exiting or kthreads, neither of which
	// will have useful user stack pointers.
	unsigned long long task_mm;
	if (!readmem(VADDR, taskp + OFF.task_struct.mm, &task_mm, sizeof(task_mm))
	    || !task_mm)
		return TRUE;

	unsigned long long sp = task_sp(taskp);
	if (!sp)
		return TRUE;

	unsigned long long vma = 0;
	if (OFF.mm_struct.mm_mt >= 0)
		vma = find_vma_mtree(task_mm + OFF.mm_struct.mm_mt, sp);
	else if (OFF.mm_struct.mm_rb >= 0)
		vma = find_vma_rbtree(task_mm + OFF.mm_struct.mm_rb, sp);
	if (!vma)
		return TRUE;

	unsigned long long vm_start, vm_end, anon_vma, vm_pgoff;
	if (!readmem(VADDR, vma + OFF.vm_area_struct.anon_vma, &anon_vma, sizeof(anon_vma)) ||
	    !anon_vma ||
	    !readmem(VADDR, vma + OFF.vm_area_struct.vm_start, &vm_start, sizeof(vm_start)) ||
	    !readmem(VADDR, vma + OFF.vm_area_struct.vm_end, &vm_end, sizeof(vm_end)) ||
	    !readmem(VADDR, vma + OFF.vm_area_struct.vm_pgoff, &vm_pgoff, sizeof(vm_pgoff)))
		return TRUE;

	// Construct a range of indices we would like to retain. This is the
	// range of stack pages starting with the stack pointer, and continuing
	// to the top of the stack vma, or until a limit of 128 pages per task
	// is reached.
	unsigned long long pgoff_start = (sp - vm_start) >> PAGESHIFT();
	pgoff_start += vm_pgoff;
	unsigned long pgoff_end = (vm_end - vm_start) >> PAGESHIFT();
	pgoff_end += vm_pgoff;
	if (pgoff_start + 128 < pgoff_end)
		pgoff_end = pgoff_start + 128;

	struct task_stack stack = {anon_vma | 1, pgoff_start, pgoff_end};
	if (!append_task_stack(&stack))
		return FALSE;

	return TRUE;
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

static int count_retained;
static int count_checked;
static int count_cached;
int retain_anon_vma(unsigned long long mapping, unsigned long long index)
{
	static struct {
		unsigned long long mapping;
		struct task_stack *result;
	} cache;

	if (!stacks || !(mapping & 1))
		return FALSE;

	if (mapping != cache.mapping) {
		count_checked++;
		struct task_stack search = {mapping, 0, 0};
		struct task_stack *result = bsearch(&search, stacks, stacks_count,
						sizeof(search), &stack_compar);
		if (!result)
			return FALSE;

		cache.mapping = mapping;
		cache.result = result;

	} else {
		count_cached++;
	}

	int res = index >= cache.result->index_start && index < cache.result->index_end;
	if (res)
		count_retained++;
	return res;
}

void __report(void)
{
	printf("Retained: %d searched: %d, cached: %d\n", count_retained, count_checked, count_cached);
	printf("Recorded %zu stack anon_vmas\n", stacks_count);
}

int load_task_stacks(void)
{
	if (!_load_sym_off())
		return FALSE;
	for_each_task(&record_task_stack);

	// Shrink the stack array to fit
	struct task_stack *tmp = realloc(stacks, stacks_count * sizeof(*tmp));
	if (!tmp)
		return FALSE;
	stacks = tmp;
	stacks_alloc = stacks_count;

	// Sort the stacks
	qsort(stacks, stacks_count, sizeof(*stacks), &stack_compar);
	atexit(__report);
	return TRUE;
}
