#ifndef RBTREE_H_
#define RBTREE_H_
#include <stdbool.h>
unsigned long find_vma_rbtree(unsigned long rb_root, unsigned long address);
bool vma_rbtree_init(void);
#endif // RBTREE_H_
