#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <bpf/btf.h>
#include <bpf/libbpf_legacy.h>
#include "makedumpfile.h"
#include "kallsyms.h"
#include "btf_info.h"

struct btf_arr_elem {
	struct btf *btf;
	char *module;
};

static struct btf_arr_elem **btf_arr = NULL;
static int btf_arr_len = 0;
static int btf_arr_cap = 0;

/* makedumpfile & extensions' .init_ktypes section range array */
static struct section_range **sr = NULL;
static int sr_len = 0;
static int sr_cap = 0;

/* Which mod's btf should be inited? */
static char **mods = NULL;
static int mods_len = 0;
static int mods_cap = 0;

static bool add_ktype_modname(char *modname)
{
	return push_uniq_str((void ***)&mods, &mods_len, &mods_cap, modname);
}

bool check_ktypes_require_modname(char *modname, int *total)
{
	if (total)
		*total = mods_len;
	for (int i = 0; i < mods_len; i++) {
		if (!strcmp(modname, mods[i]))
			return true;
	}
	return false;
}

static void cleanup_ktypes_modname(void)
{
	if (mods)
		free(mods);
}

/*
 * Used by makedumpfile and extensions, to register their .init_ktypes section,
 * so btf_info can know which module/type should be inited.
*/
REGISTER_SECTION(ktype)

static void cleanup_ktypes_section_range(void)
{
	for (int i = 0; i < sr_len; i++) {
		free(sr[i]);
	}
	if (sr)
		free(sr);
}

static bool find_member_recursive(struct btf *btf, int struct_typeid,
				int base_offset, struct ktype_info *ki)
{
	const struct btf_type *st;
	struct btf_member *bm;
	int i, vlen;

	struct_typeid = btf__resolve_type(btf, struct_typeid);
	st = btf__type_by_id(btf, struct_typeid);

	if (!st)
		return false;

	if (BTF_INFO_KIND(st->info) != BTF_KIND_STRUCT &&
	    BTF_INFO_KIND(st->info) != BTF_KIND_UNION)
		return false;

	vlen = BTF_INFO_VLEN(st->info);
	bm = btf_members(st);

	for (i = 0; i < vlen; i++, bm++) {
		const char *name = btf__name_by_offset(btf, bm->name_off);
		int member_bit_offset = btf_member_bit_offset(st, i) + base_offset;
		int member_typeid = btf__resolve_type(btf, bm->type);
		const struct btf_type *mt = btf__type_by_id(btf, member_typeid);

		if (name && strcmp(name, ki->member_name) == 0) {
			ki->member_bit_offset = member_bit_offset;
			ki->member_bit_sz = btf_member_bitfield_size(st, i);
			ki->member_size = btf__resolve_size(btf, member_typeid);
			return true;
		}

		if (!name || !name[0]) {
			if (BTF_INFO_KIND(mt->info) == BTF_KIND_STRUCT ||
			    BTF_INFO_KIND(mt->info) == BTF_KIND_UNION) {
				if (find_member_recursive(btf, member_typeid,
							member_bit_offset, ki))
					return true;
			}
		}
	}
	return false;
}

static bool get_ktype_info(struct ktype_info *ki, char *mod_to_resolve)
{
	int i, j, start_id;

	if (mod_to_resolve != NULL) {
		if (strcmp(ki->modname, mod_to_resolve) != 0)
			/* Exit safely */
			return true;
	}

	for (i = 0; i < btf_arr_len; i++) {
		if (strcmp(btf_arr[i]->module, ki->modname) != 0)
			continue;
		/*
		 * vmlinux(btf_arr[0])'s typeid is 1~vmlinux_type_cnt,
		 * modules(btf_arr[1...])'s typeid is vmlinux_type_cnt~btf__type_cnt
		 */
		start_id = (i == 0 ? 1 : btf__type_cnt(btf_arr[0]->btf));

		for (j = start_id; j < btf__type_cnt(btf_arr[i]->btf); j++) {
			const struct btf_type *bt =
				btf__type_by_id(btf_arr[i]->btf, j);
			const char *name =
				btf__name_by_offset(btf_arr[i]->btf, bt->name_off);

			if (name && strcmp(ki->struct_name, name) == 0) {
				if (ki->member_name != NULL) {
					/* Retrieve member info */
					if (!find_member_recursive(btf_arr[i]->btf,
								   j, 0, ki)) {
						fprintf(stderr, "%s: Not find member %s in %s\n",
							__func__, ki->member_name,
							ki->struct_name);						
						return false;
					}
				}
				ki->struct_size = btf__resolve_size(btf_arr[i]->btf, j);
				return true;
			}
		}
		if (j >= btf__type_cnt(btf_arr[i]->btf)) {
			fprintf(stderr, "%s: Not find struct/union %s in %s\n",
				__func__, ki->struct_name, ki->modname);						
			return false;			
		}
	}

	fprintf(stderr, "%s: Module %s not found\n", __func__, ki->modname);
	return false;
}

static bool add_to_btf_arr(struct btf *btf, char *module_name)
{
	struct btf_arr_elem *new_p;

	new_p = malloc(sizeof(struct btf_arr_elem));
	if (!new_p)
		goto no_mem;

	new_p->btf = btf;
	new_p->module = module_name;

	return add_to_arr((void ***)&btf_arr, &btf_arr_len, &btf_arr_cap, new_p);

no_mem:
	fprintf(stderr, "%s: Not enough memory!\n", __func__);
	return false;
}

INIT_KERN_SYM(__start_BTF);
INIT_KERN_SYM(__stop_BTF);

/*
 * Makedumpfile's .init_ktypes section
*/
extern struct ktype_info __start_init_ktypes[];
extern struct ktype_info __stop_init_ktypes[];

bool init_kernel_btf(void)
{
	uint64_t size;
	struct btf *btf;
	int i;
	struct ktype_info **p;
	char *buf = NULL;
	bool ret = false;

	uint64_t start_btf = GET_KERN_SYM(__start_BTF);
	uint64_t stop_btf = GET_KERN_SYM(__stop_BTF);
	if (!start_btf || !stop_btf) {
		fprintf(stderr, "%s: symbol __start/stop_BTF not found!\n", __func__);
		goto out;
	}

	if (!register_ktype_section((char *)__start_init_ktypes,
				    (char *)__stop_init_ktypes))
		return ret;

	size = stop_btf - start_btf;
	buf = (char *)malloc(size);
	if (!buf) {
		fprintf(stderr, "%s: Not enough memory!\n", __func__);
		goto out;
	}
	readmem(VADDR, start_btf, buf, size);
	btf = btf__new(buf, size);

	if (libbpf_get_error(btf) != 0 ||
	    add_to_btf_arr(btf, strdup("vmlinux")) == false) {	
		fprintf(stderr, "%s: init vmlinux btf fail\n", __func__);
		goto out;
	}

	for (i = 0; i < sr_len; i++) {
		for (p = (struct ktype_info **)(sr[i]->start);
		     p < (struct ktype_info **)(sr[i]->stop);
		     p++)
			if (get_ktype_info(*p, "vmlinux") == false)
				goto out;
	}

	ret = true;
out:
	if (buf)
		free(buf);
	return ret;
}