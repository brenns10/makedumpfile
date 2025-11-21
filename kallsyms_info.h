/*
 * kallsyms_info.h
 *
 * TODO LICENSE
 */
#ifndef _KALLSYMS_INFO_H
#define _KALLSYMS_INFO_H

#include <stddef.h>

int load_kallsyms(void);
size_t kallsyms_lookup(const char *name);

#endif // _KALLSYMS_INFO_H
