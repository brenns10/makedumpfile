#include <stdio.h>
#include <stdbool.h>
#include "../btf_info.h"
#include "../kallsyms.h"
#include "../makedumpfile.h"

static unsigned char mt_slots[4] = {0};
static unsigned char mt_pivots[4] = {0};
static unsigned long mt_max[4] = {0};

INIT_KERN_SYM(mt_slots);
INIT_KERN_SYM(mt_pivots);

INIT_KERN_STRUCT(maple_tree);
INIT_KERN_STRUCT(maple_node);
INIT_KERN_STRUCT_MEMBER(maple_tree, ma_root);
INIT_KERN_STRUCT_MEMBER(maple_node, ma64);
INIT_KERN_STRUCT_MEMBER(maple_node, mr64);
INIT_KERN_STRUCT_MEMBER(maple_node, slot);
INIT_KERN_STRUCT_MEMBER(maple_arange_64, pivot);
INIT_KERN_STRUCT_MEMBER(maple_arange_64, slot);
INIT_KERN_STRUCT_MEMBER(maple_range_64, pivot);
INIT_KERN_STRUCT_MEMBER(maple_range_64, slot);

#define MEMBER_OFF(S, M) \
	GET_KERN_STRUCT_MEMBER_MOFF(S, M) / 8

#define MAPLE_BUFSIZE			512

enum {
	maple_dense_enum,
	maple_leaf_64_enum,
	maple_range_64_enum,
	maple_arange_64_enum,
};

#define MAPLE_NODE_MASK			255UL
#define MAPLE_NODE_TYPE_MASK		0x0F
#define MAPLE_NODE_TYPE_SHIFT		0x03
#define XA_ZERO_ENTRY			xa_mk_internal(257)

static unsigned long xa_mk_internal(unsigned long v)
{
	return (v << 2) | 2;
}

static bool xa_is_internal(unsigned long entry)
{
	return (entry & 3) == 2;
}

static bool xa_is_node(unsigned long entry)
{
	return xa_is_internal(entry) && entry > 4096;
}

static bool xa_is_value(unsigned long entry)
{
	return entry & 1;
}

static bool xa_is_zero(unsigned long entry)
{
	return entry == XA_ZERO_ENTRY;
}

static unsigned long xa_to_internal(unsigned long entry)
{
	return entry >> 2;
}

static unsigned long xa_to_value(unsigned long entry)
{
	return entry >> 1;
}

static unsigned long mte_to_node(unsigned long entry)
{
        return entry & ~MAPLE_NODE_MASK;
}

static unsigned long mte_node_type(unsigned long maple_enode_entry)
{
	return (maple_enode_entry >> MAPLE_NODE_TYPE_SHIFT) &
		MAPLE_NODE_TYPE_MASK;
}

static unsigned long mt_slot(void **slots, unsigned char offset)
{
       return (unsigned long)slots[offset];
}

static bool ma_is_leaf(unsigned long type)
{
	return type < maple_range_64_enum;
}

static bool mte_is_leaf(unsigned long maple_enode_entry)
{
       return ma_is_leaf(mte_node_type(maple_enode_entry));
}

static void mt_dump_entry(unsigned long entry, unsigned long min,
			unsigned long max, unsigned int depth,
			unsigned long **array_out, int *array_len,
			int *array_cap)
{
	if (entry == 0)
		return;

	add_to_arr((void ***)array_out, array_len, array_cap, (void *)entry);
}

static void mt_dump_node(unsigned long entry, unsigned long min,
			unsigned long max, unsigned int depth,
			unsigned long **array_out, int *array_len,
			int *array_cap);

static void mt_dump_range64(unsigned long entry, unsigned long min,
			unsigned long max, unsigned int depth,
			unsigned long **array_out, int *array_len,
			int *array_cap)
{
	unsigned long maple_node_m_node = mte_to_node(entry);
	char node_buf[MAPLE_BUFSIZE];
	bool leaf = mte_is_leaf(entry);
	unsigned long first = min, last;
	int i;
	char *mr64_buf;

	readmem(VADDR, maple_node_m_node, node_buf, GET_KERN_STRUCT_SSIZE(maple_node));
	mr64_buf = node_buf + MEMBER_OFF(maple_node, mr64);

	for (i = 0; i < mt_slots[maple_range_64_enum]; i++) {
		last = max;

		if (i < (mt_slots[maple_range_64_enum] - 1))
			last = ULONG(mr64_buf + MEMBER_OFF(maple_range_64, pivot) +
				     sizeof(ulong) * i);

		else if (!VOID_PTR(mr64_buf + MEMBER_OFF(maple_range_64, slot) +
			  sizeof(void *) * i) &&
			 max != mt_max[mte_node_type(entry)])
			break;
		if (last == 0 && i > 0)
			break;
		if (leaf)
			mt_dump_entry(mt_slot((void **)(mr64_buf +
						      MEMBER_OFF(maple_range_64, slot)), i),
				first, last, depth + 1, array_out, array_len, array_cap);
		else if (VOID_PTR(mr64_buf + MEMBER_OFF(maple_range_64, slot) +
				  sizeof(void *) * i)) {
			mt_dump_node(mt_slot((void **)(mr64_buf +
						     MEMBER_OFF(maple_range_64, slot)), i),
				first, last, depth + 1, array_out, array_len, array_cap);
		}

		if (last == max)
			break;
		if (last > max) {
			printf("node %p last (%lu) > max (%lu) at pivot %d!\n",
				mr64_buf, last, max, i);
			break;
		}
		first = last + 1;
	}
}

static void mt_dump_arange64(unsigned long entry, unsigned long min,
			unsigned long max, unsigned int depth,
			unsigned long **array_out, int *array_len,
			int *array_cap)
{
	unsigned long maple_node_m_node = mte_to_node(entry);
	char node_buf[MAPLE_BUFSIZE];
	unsigned long first = min, last;
	int i;
	char *ma64_buf;

	readmem(VADDR, maple_node_m_node, node_buf, GET_KERN_STRUCT_SSIZE(maple_node));
	ma64_buf = node_buf + MEMBER_OFF(maple_node, ma64);

	for (i = 0; i < mt_slots[maple_arange_64_enum]; i++) {
		last = max;

		if (i < (mt_slots[maple_arange_64_enum] - 1))
			last = ULONG(ma64_buf + MEMBER_OFF(maple_arange_64, pivot) +
				     sizeof(void *) * i);
		else if (!VOID_PTR(ma64_buf + MEMBER_OFF(maple_arange_64, slot) +
				   sizeof(void *) * i))
			break;
		if (last == 0 && i > 0)
			break;

		if (ULONG(ma64_buf + MEMBER_OFF(maple_arange_64, slot) + sizeof(void *) * i))
			mt_dump_node(mt_slot((void **)(ma64_buf +
						      MEMBER_OFF(maple_arange_64, slot)), i),
				first, last, depth + 1, array_out, array_len, array_cap);

		if (last == max)
			break;
		if (last > max) {
			printf("node %p last (%lu) > max (%lu) at pivot %d!\n",
				ma64_buf, last, max, i);
			break;
		}
		first = last + 1;
	}
}

static void mt_dump_node(unsigned long entry, unsigned long min,
			unsigned long max, unsigned int depth,
			unsigned long **array_out, int *array_len,
			int *array_cap)
{
	unsigned long maple_node = mte_to_node(entry);
	unsigned long type = mte_node_type(entry);
	int i;
	char node_buf[MAPLE_BUFSIZE];

	readmem(VADDR, maple_node, node_buf, GET_KERN_STRUCT_SSIZE(maple_node));

	switch (type) {
	case maple_dense_enum:
		for (i = 0; i < mt_slots[maple_dense_enum]; i++) {
			if (min + i > max)
				printf("OUT OF RANGE: ");
			mt_dump_entry(mt_slot((void **)(node_buf + MEMBER_OFF(maple_node, slot)), i),
				min + i, min + i, depth, array_out, array_len, array_cap);
		}
		break;
	case maple_leaf_64_enum:
	case maple_range_64_enum:
		mt_dump_range64(entry, min, max, depth, array_out, array_len, array_cap);
		break;
	case maple_arange_64_enum:
		mt_dump_arange64(entry, min, max, depth, array_out, array_len, array_cap);
		break;
	default:
		printf(" UNKNOWN TYPE\n");
	}	
}

unsigned long *mt_dump(unsigned long mt, int *array_len)
{
	char tree_buf[MAPLE_BUFSIZE];
	unsigned long entry;
	unsigned long *array_out = NULL;
	int array_cap = 0;
	*array_len = 0;

	readmem(VADDR, mt, tree_buf, GET_KERN_STRUCT_SSIZE(maple_tree));
	entry = ULONG(tree_buf + MEMBER_OFF(maple_tree, ma_root));

	if (xa_is_node(entry))
		mt_dump_node(entry, 0, mt_max[mte_node_type(entry)], 0,
				&array_out, array_len, &array_cap);
	else if (entry)
		mt_dump_entry(entry, 0, 0, 0, &array_out, array_len, &array_cap);
	else
		printf("(empty)\n");

	return array_out;
}

bool maple_init(void)
{
	unsigned long mt_slots_ptr;
	unsigned long mt_pivots_ptr;

	mt_slots_ptr = GET_KERN_SYM(mt_slots);
	mt_pivots_ptr = GET_KERN_SYM(mt_pivots);

	if (mt_slots_ptr == 0 || mt_pivots_ptr == 0) {
		printf("Invalid mt_slots/mt_pivots address\n");
		return false;
	}
	if (GET_KERN_STRUCT_SSIZE(maple_tree) > MAPLE_BUFSIZE ||
	    GET_KERN_STRUCT_SSIZE(maple_node) > MAPLE_BUFSIZE) {
		printf("MAPLE_BUFSIZE should be larger than maple_node/tree struct\n");
		return false;
	}

	readmem(VADDR, mt_slots_ptr, mt_slots, sizeof(mt_slots));
	readmem(VADDR, mt_pivots_ptr, mt_pivots, sizeof(mt_pivots));

	mt_max[maple_dense_enum]           = mt_slots[maple_dense_enum];
	mt_max[maple_leaf_64_enum]         = ULONG_MAX;
	mt_max[maple_range_64_enum]        = ULONG_MAX;
	mt_max[maple_arange_64_enum]       = ULONG_MAX;

	return true;
}