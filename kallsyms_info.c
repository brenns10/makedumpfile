#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "dwarf_info.h"
#include "makedumpfile.h"
#include "kallsyms_info.h"

/**
 * This struct contains the tables necessary to reconstruct kallsyms names.
 *
 * vmlinux (core kernel) kallsyms names are compressed using table compression.
 * There is some description of it in the kernel's "scripts/kallsyms.c", but
 * this is a brief overview that should make the code below comprehensible.
 *
 * Table compression uses the remaining 128 characters not defined by ASCII and
 * maps them to common substrings (e.g. the prefix "write_"). Each name is
 * represented as a sequence of bytes which refers to strings in this table.
 * The two arrays below comprise this table:
 *
 *   - token_table: this is one long string with all of the tokens concatenated
 *     together, e.g. "a\0b\0c\0...z\0write_\0read_\0..."
 *   - token_index: this is a 256-entry long array containing the index into
 *     token_table where you'll find that token's string.
 *
 * To decode a string, for each byte you simply index into token_index, then use
 * that to index into token_table, and copy that string into your buffer.
 *
 * The actual kallsyms symbol names are concatenated into a buffer called
 * "names". The first byte in a name is the length (in tokens, not decoded
 * bytes) of the symbol name. The remaining "length" bytes are decoded via the
 * table as described above. The first decoded byte is a character representing
 * what type of symbol this is (e.g. text, data structure, etc).
 */
struct kallsyms {
	int num_syms;
	uint8_t *names;
	size_t names_len;
	char *token_table;
	size_t token_table_len;
	uint16_t *token_index;
	uintptr_t *addresses;
	bool long_names, ready;
};

static bool read_u8(size_t addr, uint8_t *result)
{
	return readmem(VADDR, addr, result, sizeof(*result)) == sizeof(*result);
}

static bool read_int(size_t addr, int *result)
{
	return readmem(VADDR, addr, result, sizeof(*result)) == sizeof(*result);
}

static bool read_ulong(size_t addr, uintptr_t *result)
{
	return readmem(VADDR, addr, result, sizeof(*result)) == sizeof(*result);
}

/*
 * Since 73bbb94466fd3 ("kallsyms: support "big" kernel symbols"), the
 * "kallsyms_names" array may use the most significant bit to indicate that the
 * initial element for each symbol (normally representing the number of tokens
 * in the symbol) requires two bytes.
 *
 * Unfortunately, that means that values 128-255 are now ambiguous: on older
 * kernels, they should be interpreted literally, but on newer kernels, they
 * require treating as a two byte sequence. Since the commit included no changes
 * to the symbol names or vmcoreinfo, there's no way to detect it except via
 * heuristics.
 *
 * The commit in question is a new feature and not likely to be backported to
 * stable, so our heuristic is that it was first included in kernel 6.1.
 * However, we first check the environment variable MAKEDUMPFILE_KALLSYMS_LONG:
 * if it exists, then we use its first character to determine our behavior: 1,
 * y, Y all indicate that we should use long names. 0, n, N all indicate that we
 * should not.
 */
static bool guess_long_names(void)
{
	const char *env = getenv("MAKEDUMPFILE_KALLSYMS_LONG");
	if (env) {
		if (*env == '1' || *env == 'y' || *env == 'Y')
			return true;
		else if (*env == '0' || *env == 'n' || *env == 'N')
			return false;
	}

	char *p = info->release;
	long major = strtol(p, &p, 10);
	long minor = 0;
	if (*p == '.')
		minor = strtol(p + 1, NULL, 10);

	return (major == 6 && minor >= 1) || major > 6;
}

/**
 * Copy the kallsyms names tables from the program into host memory.
 * @param prog Program to read from
 * @param kr kallsyms_reader to populate
 * @param vi vmcoreinfo for the program
 */
static int kallsyms_load_tables(struct kallsyms *kr)
{
	const size_t token_index_size = (UINT8_MAX + 1) * sizeof(uint16_t);
	uint64_t last_token;
	size_t names_idx;
	uint8_t data, len_u8;
	int len;

	// Read num_syms from vmcore (bswap is done for us already)
	if (!read_int(SYMBOL(kallsyms_num_syms), &kr->num_syms))
		return FALSE;

	// Read the constant-sized token_index table (256 entries)
	kr->token_index = malloc(token_index_size);
	if (!kr->token_index) {
		ERRMSG("Can't allocate kallsyms token_index buffer: %s\n", strerror(errno));
		return FALSE;
	}
	if (!readmem(VADDR, SYMBOL(kallsyms_token_index), kr->token_index,
		      token_index_size))
		return FALSE;

	// Find the end of the last token, so we get the overall length of
	// token_table. Then copy the token_table into host memory.
	last_token = SYMBOL(kallsyms_token_table) + kr->token_index[UINT8_MAX];
	do {
		if (!read_u8(last_token, &data))
			return FALSE;
		last_token++;
	} while (data);
	kr->token_table_len = last_token - SYMBOL(kallsyms_token_table) + 1;
	kr->token_table = malloc(kr->token_table_len);
	if (!kr->token_table) {
		ERRMSG("Can't allocate kallsyms token_table buffer: %s\n", strerror(errno));
		return FALSE;
	}
	if (!readmem(VADDR, SYMBOL(kallsyms_token_table), kr->token_table,
		     kr->token_table_len))
		return FALSE;

	// Ensure that all members of token_index are in-bounds for indexing
	// into token_table.
	for (size_t i = 0; i <= UINT8_MAX; i++) {
		if (kr->token_index[i] >= kr->token_table_len) {
			ERRMSG("kallsyms: token_index out of bounds (token_index[%zu] = %u >= %zu)",
			        i, kr->token_index[i], kr->token_table_len);
			return FALSE;
		}
	}

	// Now find the end of the names array by skipping through it, then copy
	// that into host memory.
	names_idx = 0;
	kr->long_names = guess_long_names();
	for (size_t i = 0; i < kr->num_syms; i++) {
		if (!read_u8(SYMBOL(kallsyms_names) + names_idx, &len_u8))
			return FALSE;
		len = len_u8;
		if ((len & 0x80) && kr->long_names) {
			if (__builtin_add_overflow(names_idx, 1, &names_idx)) {
				ERRMSG("Could not find end of kallsyms_names");
				return FALSE;
			}
			if (read_u8(SYMBOL(kallsyms_names) + names_idx, &len_u8))
				return FALSE;
			// 73bbb94466fd3 ("kallsyms: support "big" kernel
			// symbols") mentions that ULEB128 is used, but only
			// implements the ability to encode lengths with 2
			// bytes, for a maximum value of 16k. It's possible in
			// the future we may need to support larger sizes, but
			// it's difficult to predict the future of the kallsyms
			// format. For now, just check that there's no third
			// byte to the length.
			if (len_u8 & 0x80) {
				ERRMSG("Unexpected 3-byte length encoding in kallsyms names");
				return FALSE;
			}
			len = (len & 0x7F) | (len_u8 << 7);
		}
		if (__builtin_add_overflow(names_idx, len + 1, &names_idx)) {
			ERRMSG("couldn't find end of kallsyms_names");
			return FALSE;
		}
	}
	kr->names_len = names_idx;
	kr->names = malloc(names_idx);
	if (!kr->names) {
		ERRMSG("Can't allocate kallsyms names buffer: %s\n", strerror(errno));
		return FALSE;
	}
	if (!readmem(VADDR, SYMBOL(kallsyms_names), kr->names, names_idx))
		return FALSE;

	return TRUE;
}

/**
 * Extract the symbol name and type
 * @param kr Registry containing kallsyms data
 * @param names_bb A binary buffer tracking our position within the
 *   `kallsyms_names` array
 * @param sb Buffer to write output symbol to
 * @param[out] kind_ret Where to write the symbol kind data
 * @returns NULL on success, or an error
 */
static bool
kallsyms_match(struct kallsyms *kr, uint8_t *tokens, size_t tokens_len,
	       const char *string, size_t string_len)
{
	bool skipped_first = false;

	while (string_len && tokens_len) {
		char *token_ptr = &kr->token_table[kr->token_index[*tokens]];
		while (*token_ptr) {
			if (skipped_first) {
				if (string_len <= 0 || *token_ptr != *string)
					goto out;
				string++;
				string_len--;
			} else {
				skipped_first = true;
			}
			token_ptr++;
		}
		tokens++;
		tokens_len--;
	}

out:
	return string_len == 0 && tokens_len == 0;
}

/**
 * Find a symbol name in a kallsyms_reader
 */
static ssize_t kallsyms_search(struct kallsyms *kr, const char *name)
{
	size_t len = strlen(name);
	size_t token_index = 0;
	for (ssize_t i = 0; i < kr->num_syms; i++) {
		size_t token_count = kr->names[token_index++];
		if (token_count & 0x80 && kr->long_names)
			token_count = ((token_count & 0x7F) << 7) | kr->names[token_index++];

		if (kallsyms_match(kr, &kr->names[token_index], token_count, name, len))
			return i;

		token_index += token_count;
	}
	return -1;
}

/** Compute an address via the CONFIG_KALLSYMS_ABSOLUTE_PERCPU method*/
static uint64_t absolute_percpu(uintptr_t base, int val)
{
	if (val >= 0)
		return (uint64_t) val;
	else
		return base - 1 - val;
}

/**
 * Load the kallsyms address information from a vmcore
 *
 * Just as symbol name loading is complex, so is address loading. Addresses may
 * be stored directly as an array of pointers, but more commonly, they are
 * stored as an array of 32-bit integers which are related to an offset. This
 * function decodes the addresses into a plain array of 64-bit addresses.
 *
 * @param prog The program to read from
 * @param kr The symbol registry to fill
 * @param vi vmcoreinfo containing necessary symbols
 * @returns NULL on success, or error
 */
static int
kallsyms_load_addresses(struct kallsyms *kr)
{
	kr->addresses = calloc(kr->num_syms, sizeof(kr->addresses[0]));
	if (!kr->addresses) {
		ERRMSG("Cannot allocate kallsyms addresses table: %s\n", strerror(errno));
		return FALSE;
	}

	if (SYMBOL(kallsyms_addresses) != NOT_FOUND_SYMBOL) {
		if (!readmem(VADDR, SYMBOL(kallsyms_addresses), kr->addresses,
			     kr->num_syms * sizeof(kr->addresses[0])))
			return FALSE;
	} else {
		/*
		 * The kallsyms addresses are stored in an array of 4-byte
		 * values, which can be interpreted in two ways:
		 * (1) if CONFIG_KALLSYMS_ABSOLUTE_PERCPU is enabled, then
		 *     positive values are addresses, and negative values are
		 *     offsets from a base address.
		 * (2) otherwise, the 4-byte values are directly used as
		 *     addresses
		 *
		 * To decide which way to interpret the offsets, use the _stext
		 * symbol. We have the correct value from vmcoreinfo. We'll read
		 * the offsets and compute the symbol value both ways to
		 * determine the correct way to interpret addresses.
		 */
		ssize_t stext_idx = kallsyms_search(kr, "_stext");
		if (stext_idx < 0) {
			ERRMSG("Cannot interpret kallsyms addresses: no symbol _stext found\n");
			return FALSE;
		}
		uintptr_t relative_base;
		if (!read_ulong(SYMBOL(kallsyms_relative_base), &relative_base))
			return FALSE;

		int *offsets = calloc(kr->num_syms, sizeof(offsets[0]));
		if (!offsets) {
			ERRMSG("Cannot allocate temporary kallsyms offsets buffer: %s\n",
				strerror(errno));
			return FALSE;
		}
		if (!readmem(VADDR, SYMBOL(kallsyms_offsets), offsets,
				kr->num_syms * sizeof(offsets[0]))) {
			free(offsets);
			return FALSE;
		}

		uintptr_t stext_abs = relative_base + (unsigned int)offsets[stext_idx];
		uintptr_t stext_pcpu = absolute_percpu(relative_base, offsets[stext_idx]);
		if (stext_abs == SYMBOL(_stext)) {
			for (int i = 0; i < kr->num_syms; i++)
				kr->addresses[i] = relative_base + (unsigned int)offsets[i];
		} else if (stext_pcpu == SYMBOL(_stext)) {
			for (int i = 0; i < kr->num_syms; i++)
				kr->addresses[i] = absolute_percpu(relative_base, offsets[i]);
		} else {
			ERRMSG("Cannot interpret kallsyms offsets: for _stext offset %d, "
			       "neither relative base (%"PRIxPTR") nor absolute percpu "
			       "(%"PRIxPTR") matched vmcoreinfo (%llx)\n",
			       offsets[stext_idx], stext_abs, stext_pcpu, SYMBOL(_stext));
			free(offsets);
			return FALSE;
		}
		free(offsets);
	}
	return TRUE;
}

static void kallsyms_destroy(struct kallsyms *kr)
{
	free(kr->names);
	free(kr->token_index);
	free(kr->token_table);
	free(kr->addresses);
	memset(kr, 0, sizeof(*kr));
}

struct kallsyms ks;

int load_kallsyms(void)
{
	if (!(SYMBOL(kallsyms_names) && SYMBOL(kallsyms_token_table)
	      && SYMBOL(kallsyms_token_index) && SYMBOL(kallsyms_num_syms))) {
		ERRMSG(
			"The symbols: kallsyms_names, kallsyms_token_table, "
			"kallsyms_token_index, and kallsyms_num_syms were not "
			"found in VMCOREINFO. There is not enough "
			"information to load the kallsyms table."
		);
		return FALSE;
	}

	if (!kallsyms_load_tables(&ks)) {
		kallsyms_destroy(&ks);
		return FALSE;
	}

	if (!kallsyms_load_addresses(&ks)) {
		kallsyms_destroy(&ks);
		return FALSE;
	}

	ks.ready = true;
	return TRUE;
}

size_t kallsyms_lookup(const char *name)
{
	if (!ks.ready)
		return NOT_FOUND_SYMBOL;

	ssize_t index = kallsyms_search(&ks, name);
	if (index < 0)
		return NOT_FOUND_SYMBOL;

	return ks.addresses[index];
}
