#include "../makedumpfile.h"
#include "../btf_info.h"
#include "vma_rbtree.h"

INIT_KERN_STRUCT_MEMBER(vm_area_struct, vm_start);
INIT_KERN_STRUCT_MEMBER(vm_area_struct, vm_end);

INIT_OPT_KERN_STRUCT_MEMBER(vm_area_struct, vm_rb);
INIT_OPT_KERN_STRUCT_MEMBER(rb_root, rb_node);
INIT_OPT_KERN_STRUCT_MEMBER(rb_node, rb_left);
INIT_OPT_KERN_STRUCT_MEMBER(rb_node, rb_right);

#define MEMBER_OFF(S, M) \
	(GET_KERN_STRUCT_MEMBER_MOFF(S, M) / 8)

#define HAVE_MEMBER(s, m) (GET_KERN_STRUCT_MEMBER_MSIZE(s, m) != 0)

unsigned long find_vma_rbtree(unsigned long rb_root, unsigned long address)
{
	unsigned long node, vma, vm_start, vm_end, rb_left, rb_right;
	if (!readmem(VADDR, rb_root, &node, sizeof(node)))
		return 0;


	while (node > MEMBER_OFF(vm_area_struct, vm_rb)) {
		vma = node - MEMBER_OFF(vm_area_struct, vm_rb);
		if (!readmem(VADDR, vma + MEMBER_OFF(vm_area_struct, vm_start), &vm_start, sizeof(vm_start)) ||
		!readmem(VADDR, vma + MEMBER_OFF(vm_area_struct, vm_end), &vm_end, sizeof(vm_end)) ||
		!readmem(VADDR, node + MEMBER_OFF(rb_node, rb_left), &rb_left, sizeof(rb_left)) ||
		!readmem(VADDR, node + MEMBER_OFF(rb_node, rb_right), &rb_right, sizeof(rb_right)))
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

bool vma_rbtree_init(void)
{
	if (!HAVE_MEMBER(vm_area_struct, vm_rb) ||
	    !HAVE_MEMBER(rb_root, rb_node) ||
	    !HAVE_MEMBER(rb_node, rb_left) ||
	    !HAVE_MEMBER(rb_node, rb_right)) {
		ERRMSG("error: missing required vm_area_struct & rbtree definitions");
		return false;
	}
	return true;
}
