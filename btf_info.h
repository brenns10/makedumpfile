/*
 * btf_info.h
 *
 * TODO LICENSE
 */
#ifndef _BTF_INFO_H
#define _BTF_INFO_H

#include <stddef.h>

int load_btf(void);
int btf_offset(const char *structure, const char *name);
int btf_sizeof(const char *structure);
int btf_member_sizeof(const char *structure, const char *name);

#endif // _BTF_INFO_H
