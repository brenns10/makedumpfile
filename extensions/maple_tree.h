#ifndef _MAPLE_TREE_H
#define _MAPLE_TREE_H
#include <stdbool.h>
unsigned long *mt_dump(unsigned long mt, int *array_len);
bool maple_init(void);
unsigned long find_vma_mtree(unsigned long mt, unsigned long address);
#endif /* _MAPLE_TREE_H */
