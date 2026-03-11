#ifndef RBTREE_H_
#define RBTREE_H_

#include "../btf_info.h"

DECLARE_KERN_STRUCT_MEMBER(vm_area_struct, vm_rb);
DECLARE_KERN_STRUCT_MEMBER(vm_area_struct, vm_start);
DECLARE_KERN_STRUCT_MEMBER(vm_area_struct, vm_end);

DECLARE_KERN_STRUCT_MEMBER(rb_root, rb_node);
DECLARE_KERN_STRUCT_MEMBER(rb_node, rb_left);
DECLARE_KERN_STRUCT_MEMBER(rb_node, rb_right);

unsigned long find_vma_rbtree(unsigned long rb_root, unsigned long address);
bool vma_rbtree_init(void);
#endif // RBTREE_H_
