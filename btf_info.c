#include <stdint.h>
#include <stdlib.h>

#include "makedumpfile.h"
#include "kallsyms_info.h"
#include "btf_info.h"

#ifdef USEBTF
#include <linux/btf.h>

// Later libbpf versions paper over the missing declarations by adding #defines,
// but the libbpf 0.6.0 bundled with OL8 does not. Add them here to enable
// building on OL8.
#define BTF_KIND_DECL_TAG  17
#define BTF_KIND_TYPE_TAG  18
#define BTF_KIND_ENUM64    19

#include <bpf/btf.h>
#include <bpf/bpf.h>

// A BTF buffer of 128 MiB is much larger than we would expect to see. Use this
// arbitrary threshold to avoid loading too large buffers, or unexpectedly
// corrupt data.
#define BTF_TOOBIG (128 << 20)

static struct btf *btf;

int load_btf(void)
{
	size_t btf_start, btf_stop;

	btf_start = kallsyms_lookup("__start_BTF");
	btf_stop = kallsyms_lookup("__stop_BTF");
	if (!(btf_start && btf_stop)) {
		ERRMSG("btf_info: could not find __start_BTF and __stop_BTF symbols\n");
		return FALSE;
	}
	if (btf_stop < btf_start || btf_stop - btf_start > BTF_TOOBIG) {
		ERRMSG("btf_info: invalid range 0x%zx - 0x%zx\n", btf_start, btf_stop);
		return FALSE;
	}

	void *btf_raw = malloc(btf_stop - btf_start);
	if (!btf_raw) {
		ERRMSG("btf_info: could not allocate BTF buffer: %s\n", strerror(errno));
		return FALSE;
	}

	uint32_t len = btf_stop - btf_start;
	if (!readmem(VADDR, btf_start, btf_raw, len)) {
		free(btf_raw);
		return FALSE;
	}

	btf = btf__new(btf_raw, len);
	if (!btf) {
		ERRMSG("btf_info: could not create BTF object: %s\n", strerror(errno));
		free(btf);
		return FALSE;
	}

	return TRUE;
}

/* A recursive depth-first search to find a dotted member offset. Capable
 * of traversing anonymous structs & unions. */
static int resolve_member(const struct btf_type *su, const char *member,
			  const struct btf_type **member_type_ret)
{
	struct btf_member *members = btf_members(su);
	int num_members = btf_vlen(su);

	const char *end = strchr(member, '.');
	if (!end)
		end = &member[strlen(member)];
	size_t namelen = end - member;

	for (int i = 0; i < num_members; i++) {
		const struct btf_type *mt = btf__type_by_id(btf, members[i].type);

		if (members[i].name_off) {
			const char *mn = btf__name_by_offset(btf, members[i].name_off);
			if (strncmp(member, mn, namelen) == 0 && !mn[namelen]) {
				// Found a member matching the current component.
				int bit_offset = btf_member_bit_offset(su, i);
				if (member[namelen] == '.') {
					// There is another component. If this
					// is not a struct or union, it's an
					// error.
					if (!(btf_is_struct(mt) || btf_is_union(mt))) {
						return -1;
					}
					// Resolve the remaining component
					// recursively.
					int ret = resolve_member(mt, end + 1, member_type_ret);
					if (ret < 0)
						return -1;
					bit_offset += ret;
				} else if (member_type_ret) {
					*member_type_ret = mt;
				}
				return bit_offset;
			}
		} else if (btf_is_struct(mt) || btf_is_union(mt)) {
			// Recursively search within the anonymous struct or
			// union
			int ret = resolve_member(mt, member, member_type_ret);
			if (ret >= 0)
				return ret + btf_member_bit_offset(su, i);
		}
	}
	return -1;
}

static int32_t lookup_name(const char *name, int complex_only)
{
	if (strncmp("struct ", name, 7) == 0)
		return btf__find_by_name_kind(btf, name + 7, BTF_KIND_STRUCT);
	else if (strncmp("union ", name, 6) == 0 )
		return btf__find_by_name_kind(btf, name + 6, BTF_KIND_UNION);
	else if (!complex_only)
		return btf__find_by_name(btf, name);
	ERRMSG("Could not find struct/union: no type tag: \"%s\"\n", name);
	return -1;
}

int btf_offset(const char *structure, const char *member)
{
	int32_t result = lookup_name(structure, TRUE);

	if (result < 0)
		return -1;

	const struct btf_type *type = btf__type_by_id(btf, (uint32_t)result);
	int bit_offset = resolve_member(type, member, NULL);

	if (bit_offset >= 0 && bit_offset % 8 == 0) {
		return bit_offset / 8;
	}
	return -1;
}

static int __btf_sizeof(const struct btf_type *type)
{
	int count = 1;
	for (;;) {
		switch (btf_kind(type)) {
			case BTF_KIND_INT:
			case BTF_KIND_FLOAT:
			case BTF_KIND_STRUCT:
			case BTF_KIND_UNION:
			case BTF_KIND_ENUM:
			case BTF_KIND_ENUM64:
				return type->size * count;
			case BTF_KIND_PTR:
				return btf__pointer_size(btf) * count;
			case BTF_KIND_TYPEDEF:
			case BTF_KIND_VOLATILE:
			case BTF_KIND_CONST:
			case BTF_KIND_RESTRICT:
			case BTF_KIND_TYPE_TAG:
				type = btf__type_by_id(btf, type->type);
				break;
			case BTF_KIND_ARRAY:
				count *= btf_array(type)->nelems;
				type = btf__type_by_id(btf, btf_array(type)->type);
				break;
			default:
				ERRMSG("btf: Unsupported type kind for sizeof: %d\n",
				       btf_kind(type));
				return -1;
		}
	}
}

int btf_sizeof(const char *name)
{
	int32_t result = lookup_name(name, FALSE);

	if (result < 0)
		return -1;

	return __btf_sizeof(btf__type_by_id(btf, (uint32_t)result));
}

int btf_member_sizeof(const char *structure, const char *name)
{
	int32_t result = lookup_name(structure, TRUE);

	if (result < 0)
		return -1;

	const struct btf_type *type = btf__type_by_id(btf, (uint32_t)result);
	const struct btf_type *member_type;
	int offset = resolve_member(type, name, &member_type);
	if (offset < 0)
		return -1;

	return __btf_sizeof(member_type);
}
#else // !USEBTF
int load_btf(void) { return FALSE; }

int btf_offset(const char *structure, const char *name) { return -1; }

int btf_sizeof(const char *structure) { return -1; }

int btf_member_sizeof(const char *structure, const char *name) { return 1; }
#endif
