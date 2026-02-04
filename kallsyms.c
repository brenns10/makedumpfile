#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include "makedumpfile.h"
#include "kallsyms.h"
#include "btf_info.h"

static uint32_t *kallsyms_offsets = NULL;
static uint16_t *kallsyms_token_index = NULL;
static uint8_t  *kallsyms_token_table = NULL;
static uint8_t  *kallsyms_names = NULL;
static unsigned long kallsyms_relative_base = 0;
static unsigned int kallsyms_num_syms = 0;

/* makedumpfile & extensions' .init_ksyms section range array */
static struct section_range **sr = NULL;
static int sr_len = 0;
static int sr_cap = 0;

/* Which mod's kallsyms should be inited? */
static char **mods = NULL;
static int mods_len = 0;
static int mods_cap = 0;

INIT_KERN_SYM(_stext);

/*
 * Utility: add elem to arr, which can auto extend its capacity.
 * (*arr) is a pointer array, holding pointers of elem
*/
bool add_to_arr(void ***arr, int *arr_len, int *arr_cap, void *elem)
{
	void *tmp;
	int new_cap = 0;

	if (*arr == NULL) {
		*arr_len = 0;
		new_cap = 4;
	} else if (*arr_len >= *arr_cap) {
		new_cap = (*arr_cap) + ((*arr_cap) >> 1);
	}

	if (new_cap) {
		tmp = reallocarray(*arr, new_cap, sizeof(void *));
		if (!tmp)
			goto no_mem;
		*arr = tmp;
		*arr_cap = new_cap;
	}

	(*arr)[(*arr_len)++] = elem;
	return true;

no_mem:
	fprintf(stderr, "%s: Not enough memory!\n", __func__);
	return false;
}

/*
 * Utility: add uniq string to arr, which can auto extend its capacity.
*/
bool push_uniq_str(void ***arr, int *arr_len, int *arr_cap, char *str)
{
	for (int i = 0; i < (*arr_len); i++) {
		if (!strcmp((*arr)[i], str))
			/* String already exists, skip it */
			return true;
	}
	return add_to_arr(arr, arr_len, arr_cap, str);
}

static bool add_ksym_modname(char *modname)
{
	return push_uniq_str((void ***)&mods, &mods_len, &mods_cap, modname);
}

bool check_ksyms_require_modname(char *modname, int *total)
{
	if (total)
		*total = mods_len;
	for (int i = 0; i < mods_len; i++) {
		if (!strcmp(modname, mods[i]))
			return true;
	}
	return false;
}

static void cleanup_ksyms_modname(void)
{
	if (mods)
		free(mods);
}

/*
 * Used by makedumpfile and extensions, to register their .init_ksyms section.
 * so kallsyms can know which module/sym should be inited.
*/
REGISTER_SECTION(ksym)

static void cleanup_ksyms_section_range(void)
{
	for (int i = 0; i < sr_len; i++) {
		free(sr[i]);
	}
	if (sr)
		free(sr);
}

static bool is_unwanted_symbol(char *name)
{
	const char *unwanted_prefix[] = {
		"__pfx_",       // CFI symbols
		"_R",           // Rust symbols
	};
	for (int i = 0; i < sizeof(unwanted_prefix) / sizeof(char *); i++) {
		if (!strncmp(name, unwanted_prefix[i], strlen(unwanted_prefix[i])))
			return true;
	}
	return false;
}

static uint64_t absolute_percpu(uint64_t base, int32_t val)
{
	if (val >= 0)
		return (uint64_t)val;
	else
		return base - 1 - val;
}

#define BUFLEN 1024
static bool parse_kernel_kallsyms(void)
{
	char buf[BUFLEN];
	int index = 0, i, j;
	uint8_t *compressd_data;
	uint8_t *uncompressd_data;
	uint64_t stext;
	uint8_t len, len_old;
	struct ksym_info **p;

	for (i = 0; i < kallsyms_num_syms; i++) {
		memset(buf, 0, BUFLEN);
		len = kallsyms_names[index];
		if (len & 0x80) {
			index++;
			len_old = len;
			len = kallsyms_names[index];
			if (len & 0x80) {
				fprintf(stderr, "%s: BUG! Unexpected 3-byte length,"
					" should be detected in init_kernel_kallsyms()\n",
					__func__);
				goto out;
			}
			len = (len_old & 0x7F) | (len << 7);
		}
		index++;

		compressd_data = &kallsyms_names[index];
		index += len;
		while (len--) {
			uncompressd_data = &kallsyms_token_table[kallsyms_token_index[*compressd_data]];
			if (strlen(buf) + strlen((char *)uncompressd_data) >= BUFLEN) {
				goto next_symbol;
			}
			strcat(buf, (char *)uncompressd_data);
			compressd_data++;
		}
		if (is_unwanted_symbol(&buf[1]))
			goto next_symbol;

		/* Now check if the symbol is we wanted */
		for (j = 0; j < sr_len; j++) {
			for (p = (struct ksym_info **)(sr[j]->start);
			     p < (struct ksym_info **)(sr[j]->stop);
			     p++) {
				if (!strcmp((*p)->modname, "vmlinux") &&
				    !strcmp((*p)->symname, &buf[1])) {
					(*p)->value = kallsyms_offsets[i];
				}
			}
		}
next_symbol:
	}

	/* Now refresh the absolute each kallsyms address
	 *
	 * Kallsyms originally stored absolute symbol addresses in a plain
	 * array called "kallsyms_addresses". This strategy was called
	 * "absolute kallsyms". In Linux v4.6, commit 2213e9a66bb87 ("kallsyms:
	 * add support for relative offsets in kallsyms address table"),
	 * introduced two ways of storing symbol addresses relative two a base
	 * address, so that 64-bit architectures could use 32-bit arrays. These
	 * methods were CONFIG_KALLSYMS_BASE_RELATIVE and
	 * CONFIG_KALLSYMS_ABSOLUTE_PERCPU. The ABSOLUTE_PERCPU mechanism was
	 * used by architectures like x86_64 with a percpu address range near
	 * 0x0, but kernel address range in the negative address space. Some
	 * architectures, namely tile and ia64, had to continue using absolute
	 * kallsyms due to very large gaps in their address spaces.
	 * 
	 * After both architectures were removed, absolute percpu was dropped
	 * in v6.11 commit 64e166099b69b ("kallsyms: get rid of code for
	 * absolute kallsyms"). In v6.15, the x86_64 percpu address range was
	 * moved away from 0x0, and as a result ABSOLUTE_PERCPU was no longer
	 * required. It was dropped in 01157ddc58dc2 ("kallsyms: Remove
	 * KALLSYMS_ABSOLUTE_PERCPU"), leaving only the BASE_RELATIVE scheme
	 * (which no longer has a kconfig entry, since there is no other
	 * scheme).
	 * 
	 * This code implements support for BASE_RELATIVE and ABSOLUTE_PERCPU,
	 * but absolute percpu is not supported. The kallsyms symbols
	 * themselves were only added to vmcoreinfo in v6.0 with commit
	 * f09bddbd86619 ("vmcoreinfo: add kallsyms_num_syms symbol"). At that
	 * time, only ia64 would have used the absolute percpu mechanism. Even
	 * if these commits were backported to quite old kernels, BASE_RELATIVE
	 * and ABSOLUTE_PERCPU would suffice for most other architectures until
	 * v4.6 and earlier.
	 */
	stext = GET_KERN_SYM(_stext);
	if (SYMBOL(_stext) == absolute_percpu(kallsyms_relative_base, stext)) {
		for (j = 0; j < sr_len; j++) {
			for (p = (struct ksym_info **)(sr[j]->start);
			     p < (struct ksym_info **)(sr[j]->stop);
			     p++) {
				if (!strcmp((*p)->modname, "vmlinux")) {
					(*p)->value = absolute_percpu(
						kallsyms_relative_base, (*p)->value);
				}
			}
		}
	} else if (SYMBOL(_stext) == kallsyms_relative_base + stext) {
		for (j = 0; j < sr_len; j++) {
			for (p = (struct ksym_info **)(sr[j]->start);
			     p < (struct ksym_info **)(sr[j]->stop);
			     p++) {
				if (!strcmp((*p)->modname, "vmlinux")) {
					(*p)->value += kallsyms_relative_base;
				}
			}
		}
	} else {
		fprintf(stderr, "%s: Wrong calculate kallsyms symbol value!\n", __func__);
		goto out;
	}

	return true;
out:
	return false;
}

static bool vmcore_info_ready = false;

bool read_vmcoreinfo_kallsyms(void)
{
	READ_SYMBOL("kallsyms_names", kallsyms_names);
	READ_SYMBOL("kallsyms_num_syms", kallsyms_num_syms);
	READ_SYMBOL("kallsyms_token_table", kallsyms_token_table);
	READ_SYMBOL("kallsyms_token_index", kallsyms_token_index);
	READ_SYMBOL("kallsyms_offsets", kallsyms_offsets);
	READ_SYMBOL("kallsyms_relative_base", kallsyms_relative_base);
	vmcore_info_ready = true;
	return true;
}

/*
 * Makedumpfile's .init_ksyms section
*/
extern struct ksym_info __start_init_ksyms[];
extern struct ksym_info __stop_init_ksyms[];

bool init_kernel_kallsyms(void)
{
	const int token_index_size = (UINT8_MAX + 1) * sizeof(uint16_t);
	uint64_t last_token, len;
	unsigned char data, data_old;
	int i;
	bool ret = false;

	if (vmcore_info_ready == false) {
		fprintf(stderr, "%s: vmcoreinfo not ready for kallsyms!\n",
			__func__);
		return ret;
	}

	if (!register_ksym_section((char *)__start_init_ksyms,
				   (char *)__stop_init_ksyms))
		return ret;

	readmem(VADDR, SYMBOL(kallsyms_num_syms), &kallsyms_num_syms,
		sizeof(kallsyms_num_syms));
	readmem(VADDR, SYMBOL(kallsyms_relative_base), &kallsyms_relative_base,
		sizeof(kallsyms_relative_base));

	kallsyms_offsets = malloc(sizeof(uint32_t) * kallsyms_num_syms);
	if (!kallsyms_offsets)
		goto no_mem;
	readmem(VADDR, SYMBOL(kallsyms_offsets), kallsyms_offsets,
		kallsyms_num_syms * sizeof(uint32_t));

	kallsyms_token_index = malloc(token_index_size);
	if (!kallsyms_token_index)
		goto no_mem;
	readmem(VADDR, SYMBOL(kallsyms_token_index), kallsyms_token_index,
		token_index_size);

	last_token = SYMBOL(kallsyms_token_table) + kallsyms_token_index[UINT8_MAX];
	do {
		readmem(VADDR, last_token++, &data, 1);
	} while(data);
	len = last_token - SYMBOL(kallsyms_token_table);
	kallsyms_token_table = malloc(len);
	if (!kallsyms_token_table)
		goto no_mem;
	readmem(VADDR, SYMBOL(kallsyms_token_table), kallsyms_token_table, len);

	for (len = 0, i = 0; i < kallsyms_num_syms; i++) {
		readmem(VADDR, SYMBOL(kallsyms_names) + len, &data, 1);
		/*
		 * The 2-byte representation was added in commit 73bbb94466fd3
		 * ("kallsyms: support "big" kernel symbols") in v6.1, thus for
		 * v6.1+, they indicate a long symbol, but for kernel versions
		 * prior to v6.1, they might be ambiguous.
		 */
		if (data & 0x80) {
			len += 1;
			data_old = data;
			readmem(VADDR, SYMBOL(kallsyms_names) + len, &data, 1);
			if (data & 0x80) {
				fprintf(stderr, "%s: BUG! Unexpected 3-byte length"
					" encoding in kallsyms names\n", __func__);
				goto out;
			}
			data = (data_old & 0x7F) | (data << 7);
		}
		len += data + 1;
	}
	kallsyms_names = malloc(len);
	if (!kallsyms_names)
		goto no_mem;
	readmem(VADDR, SYMBOL(kallsyms_names), kallsyms_names, len);

	ret = parse_kernel_kallsyms();
	goto out;

no_mem:
	fprintf(stderr, "%s: Not enough memory!\n", __func__);
out:
	if (kallsyms_offsets)
		free(kallsyms_offsets);
	if (kallsyms_token_index)
		free(kallsyms_token_index);
	if (kallsyms_token_table)
		free(kallsyms_token_table);
	if (kallsyms_names)
		free(kallsyms_names);
	return ret;
}

INIT_KERN_SYM(modules);

INIT_KERN_STRUCT_MEMBER(list_head, next);
INIT_KERN_STRUCT_MEMBER(module, list);
INIT_KERN_STRUCT_MEMBER(module, name);
INIT_KERN_STRUCT_MEMBER(module, core_kallsyms);
INIT_KERN_STRUCT_MEMBER(mod_kallsyms, symtab);
INIT_KERN_STRUCT_MEMBER(mod_kallsyms, num_symtab);
INIT_KERN_STRUCT_MEMBER(mod_kallsyms, strtab);
INIT_KERN_STRUCT_MEMBER(elf64_sym, st_name);
INIT_KERN_STRUCT_MEMBER(elf64_sym, st_value);

#define MEMBER_OFF(S, M) \
	GET_KERN_STRUCT_MEMBER_MOFF(S, M) / 8

uint64_t next_list(uint64_t list)
{
	uint64_t next = 0;

	readmem(VADDR, list + MEMBER_OFF(list_head, next),
		&next, GET_KERN_STRUCT_MEMBER_MSIZE(list_head, next));
	return next;
}

bool init_module_kallsyms(void)
{
	uint64_t modules, list, value = 0, symtab = 0, strtab = 0;
	uint32_t st_name = 0;
	int num_symtab, i, j;
	struct ksym_info **p;
	char symname[512], ch;
	char *modname = NULL;
	bool ret = false;

	modules = GET_KERN_SYM(modules);
	if (!modules) {
		/* Not a failure if no module enabled */
		ret = true;
		goto out;
	}

	modname = (char *)malloc(GET_KERN_STRUCT_MEMBER_MSIZE(module, name));
	if (!modname)
		goto no_mem;

	for (list = next_list(modules); list != modules; list = next_list(list)) {
		readmem(VADDR, list - MEMBER_OFF(module, list) +
				MEMBER_OFF(module, name),
			modname, GET_KERN_STRUCT_MEMBER_MSIZE(module, name));
		if (!check_ksyms_require_modname(modname, NULL))
			continue;
		readmem(VADDR, list - MEMBER_OFF(module, list) +
				MEMBER_OFF(module, core_kallsyms) +
				MEMBER_OFF(mod_kallsyms, num_symtab),
			&num_symtab, GET_KERN_STRUCT_MEMBER_MSIZE(mod_kallsyms, num_symtab));
		readmem(VADDR, list - MEMBER_OFF(module, list) +
				MEMBER_OFF(module, core_kallsyms) +
				MEMBER_OFF(mod_kallsyms, symtab),
			&symtab, GET_KERN_STRUCT_MEMBER_MSIZE(mod_kallsyms, symtab));
		readmem(VADDR, list - MEMBER_OFF(module, list) +
				MEMBER_OFF(module, core_kallsyms) +
				MEMBER_OFF(mod_kallsyms, strtab),
			&strtab, GET_KERN_STRUCT_MEMBER_MSIZE(mod_kallsyms, strtab));
		for (i = 0; i < num_symtab; i++) {
			j = 0;
			readmem(VADDR, symtab + i * GET_KERN_STRUCT_MEMBER_SSIZE(elf64_sym, st_value) +
					MEMBER_OFF(elf64_sym, st_value),
				&value, GET_KERN_STRUCT_MEMBER_MSIZE(elf64_sym, st_value));
			readmem(VADDR, symtab + i * GET_KERN_STRUCT_MEMBER_SSIZE(elf64_sym, st_name) +
					MEMBER_OFF(elf64_sym, st_name),
				&st_name, GET_KERN_STRUCT_MEMBER_MSIZE(elf64_sym, st_name));
			do {
				readmem(VADDR, strtab + st_name + j++, &ch, 1);
			} while (ch != '\0');
			if (j == 1 || j > sizeof(symname))
				/* Skip empty or too long string */
				continue;
			readmem(VADDR, strtab + st_name, symname, j);
			if (is_unwanted_symbol(symname))
				continue;

			for (j = 0; j < sr_len; j++) {
				for (p = (struct ksym_info **)(sr[j]->start);
				     p < (struct ksym_info **)(sr[j]->stop);
				     p++) {
					if (!strcmp((*p)->modname, modname) &&
					    !strcmp((*p)->symname, symname)) {
						(*p)->value = value;
					}
				}
			}
		}
	}
	ret = true;
	goto out;
no_mem:
	fprintf(stderr, "%s: Not enough memory!\n", __func__);
out:
	if (modname)
		free(modname);
	return ret;
}

void cleanup_kallsyms(void)
{
	cleanup_ksyms_section_range();
	cleanup_ksyms_modname();
}
