/*
 * Copyright () 2026, Oracle and/or its affiliates.
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 only, as
 * published by the Free Software Foundation.
 *
 * This code is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * version 2 for more details (a copy is included in the LICENSE file that
 * accompanied this code).
 *
 * You should have received a copy of the GNU General Public License version
 * 2 along with this work; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * Please contact Oracle, 500 Oracle Parkway, Redwood Shores, CA 94065 USA
 * or visit www.oracle.com if you need additional information or have any
 * questions.
 */

#include "../makedumpfile.h"
#include "../btf_info.h"
#include "vma_rbtree.h"

INIT_MOD_STRUCT_MEMBER(vmlinux, vm_area_struct, vm_start);
INIT_MOD_STRUCT_MEMBER(vmlinux, vm_area_struct, vm_end);

INIT_OPT_MOD_STRUCT_MEMBER(vmlinux, vm_area_struct, vm_rb);
INIT_OPT_MOD_STRUCT_MEMBER(vmlinux, rb_root, rb_node);
INIT_OPT_MOD_STRUCT_MEMBER(vmlinux, rb_node, rb_left);
INIT_OPT_MOD_STRUCT_MEMBER(vmlinux, rb_node, rb_right);

#define MEMBER_OFF(S, M) \
	(GET_MOD_STRUCT_MEMBER_MOFF(vmlinux, S, M) / 8)

#define MEMBER_EXIST(S, M) \
	(MOD_STRUCT_MEMBER_EXIST(vmlinux, S, M))

int find_vma_rbtree(unsigned long rb_root, unsigned long address, unsigned long *ret)
{
	unsigned long node, vma, vm_start, vm_end, rb_left, rb_right;
	if (!readmem(VADDR, rb_root, &node, sizeof(node)))
		return FALSE;

	*ret = 0;
	while (node > MEMBER_OFF(vm_area_struct, vm_rb)) {
		vma = node - MEMBER_OFF(vm_area_struct, vm_rb);
		if (!readmem(VADDR, vma + MEMBER_OFF(vm_area_struct, vm_start), &vm_start, sizeof(vm_start)) ||
		    !readmem(VADDR, vma + MEMBER_OFF(vm_area_struct, vm_end), &vm_end, sizeof(vm_end)) ||
		    !readmem(VADDR, node + MEMBER_OFF(rb_node, rb_left), &rb_left, sizeof(rb_left)) ||
		    !readmem(VADDR, node + MEMBER_OFF(rb_node, rb_right), &rb_right, sizeof(rb_right)))
			return FALSE;

		if (address < vm_start) {
			node = rb_left;
		} else if (address >= vm_end) {
			node = rb_right;
		} else {
			*ret = vma;
			break;
		}
	}
	return TRUE;
}

bool vma_rbtree_init(void)
{
	if (!MEMBER_EXIST(vm_area_struct, vm_rb) ||
	    !MEMBER_EXIST(rb_root, rb_node) ||
	    !MEMBER_EXIST(rb_node, rb_left) ||
	    !MEMBER_EXIST(rb_node, rb_right)) {
		ERRMSG("error: missing required vm_area_struct & rbtree definitions");
		return false;
	}
	return true;
}
