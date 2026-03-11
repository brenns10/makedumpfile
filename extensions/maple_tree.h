#ifndef _MAPLE_TREE_H
#define _MAPLE_TREE_H

#include "../btf_info.h"

DECLARE_KERN_STRUCT(maple_tree);
DECLARE_KERN_STRUCT(maple_node);
DECLARE_KERN_STRUCT_MEMBER(maple_tree, ma_root);
DECLARE_KERN_STRUCT_MEMBER(maple_node, ma64);
DECLARE_KERN_STRUCT_MEMBER(maple_node, mr64);
DECLARE_KERN_STRUCT_MEMBER(maple_node, slot);
DECLARE_KERN_STRUCT_MEMBER(maple_arange_64, pivot);
DECLARE_KERN_STRUCT_MEMBER(maple_arange_64, slot);
DECLARE_KERN_STRUCT_MEMBER(maple_arange_64, meta);
DECLARE_KERN_STRUCT_MEMBER(maple_range_64, pivot);
DECLARE_KERN_STRUCT_MEMBER(maple_range_64, slot);
DECLARE_KERN_STRUCT_MEMBER(maple_range_64, meta);
DECLARE_KERN_STRUCT_MEMBER(maple_metadata, end);
unsigned long *mt_dump(unsigned long mt, int *array_len);
bool maple_init(void);
unsigned long find_vma_mtree(unsigned long mt, unsigned long address);
#endif /* _MAPLE_TREE_H */
