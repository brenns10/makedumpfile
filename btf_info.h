#ifndef _BTF_INFO_H
#define _BTF_INFO_H
#include <stdint.h>
#include <stdbool.h>

struct ktype_info {
	/********in******/
	char *modname;		// Set to search within the module, in case
				// name conflict of different modules
	char *struct_name;	// Search by struct name
	char *member_name;	// Search by member name
	bool struct_required : 1;
	bool member_required : 1;
	/********out*****/
	uint32_t member_bit_offset;	// member offset in bits
	uint32_t member_bit_sz;	// member width in bits
	uint32_t member_size;	// member size in bytes
	uint32_t struct_size;	// struct size in bytes
	int index;		// -1 if type not found
};

bool check_ktypes_require_modname(char *modname, int *total);
bool register_ktype_section(char *start, char *stop);
bool init_kernel_btf(void);
bool init_module_btf(void);
void cleanup_btf(void);

#define QUATE(x) #x
#define INIT_MOD_STRUCT_MEMBER_RQD(MOD, S, M, R)			\
	struct ktype_info _##MOD##_##S##_##M = {			\
		QUATE(MOD), QUATE(S), QUATE(M), R, R, 0, 0, 0, 0, -1	\
	};								\
	__attribute__((section(".init_ktypes"), used))			\
	struct ktype_info * _ptr_##MOD##_##S##_##M = &_##MOD##_##S##_##M

/*
 * Required types will be checked automatically before extension running.
 * Optinal types should be checked manually at extension runtime.
 */
#define INIT_MOD_STRUCT_MEMBER(MOD, S, M) \
	INIT_MOD_STRUCT_MEMBER_RQD(MOD, S, M, 1)
#define INIT_OPT_MOD_STRUCT_MEMBER(MOD, S, M) \
	INIT_MOD_STRUCT_MEMBER_RQD(MOD, S, M, 0)

#define DECLARE_MOD_STRUCT_MEMBER(MOD, S, M) \
	extern struct ktype_info _##MOD##_##S##_##M

#define GET_MOD_STRUCT_MEMBER_MOFF(MOD, S, M)  (_##MOD##_##S##_##M.member_bit_offset)
#define GET_MOD_STRUCT_MEMBER_MSIZE(MOD, S, M) (_##MOD##_##S##_##M.member_size)
#define GET_MOD_STRUCT_MEMBER_SSIZE(MOD, S, M) (_##MOD##_##S##_##M.struct_size)
#define MOD_STRUCT_MEMBER_EXIST(MOD, S, M) (_##MOD##_##S##_##M.index >= 0)
#define TYPE_EXIST(p) ((p)->index >= 0)

#define INIT_KERN_STRUCT_MEMBER(S, M) \
	INIT_MOD_STRUCT_MEMBER(vmlinux, S, M)
#define INIT_OPT_KERN_STRUCT_MEMBER(S, M) \
	INIT_OPT_MOD_STRUCT_MEMBER(vmlinux, S, M)

#define DECLARE_KERN_STRUCT_MEMBER(S, M) \
	DECLARE_MOD_STRUCT_MEMBER(vmlinux, S, M)

#define GET_KERN_STRUCT_MEMBER_MOFF(S, M)  GET_MOD_STRUCT_MEMBER_MOFF(vmlinux, S, M)
#define GET_KERN_STRUCT_MEMBER_MSIZE(S, M) GET_MOD_STRUCT_MEMBER_MSIZE(vmlinux, S, M)
#define GET_KERN_STRUCT_MEMBER_SSIZE(S, M) GET_MOD_STRUCT_MEMBER_SSIZE(vmlinux, S, M)
#define KERN_STRUCT_MEMBER_EXIST(S, M) MOD_STRUCT_MEMBER_EXIST(vmlinux, S, M)

#define INIT_MOD_STRUCT_RQD(MOD, S, R)				\
	struct ktype_info _##MOD##_##S = {			\
		QUATE(MOD), QUATE(S), 0, R, 0, 0, 0, 0, 0, -1	\
	};							\
	__attribute__((section(".init_ktypes"), used))		\
	struct ktype_info * _ptr_##MOD##_##S = &_##MOD##_##S

#define INIT_MOD_STRUCT(MOD, S) INIT_MOD_STRUCT_RQD(MOD, S, 1)
#define INIT_OPT_MOD_STRUCT(MOD, S) INIT_MOD_STRUCT_RQD(MOD, S, 0)

#define DECLARE_MOD_STRUCT(MOD, S) \
	extern struct ktype_info _##MOD##_##S;

#define GET_MOD_STRUCT_SSIZE(MOD, S) (_##MOD##_##S.struct_size)
#define MOD_STRUCT_EXIST(MOD, S) (_##MOD##_##S.index >= 0)

#define INIT_KERN_STRUCT(S) INIT_MOD_STRUCT(vmlinux, S)
#define INIT_OPT_KERN_STRUCT(S) INIT_OPT_MOD_STRUCT(vmlinux, S)

#define DECLARE_KERN_STRUCT(S) \
	DECLARE_MOD_STRUCT(vmlinux, S)

#define GET_KERN_STRUCT_SSIZE(S) GET_MOD_STRUCT_SSIZE(vmlinux, S)
#define KERN_STRUCT_EXIST(S) MOD_STRUCT_EXIST(vmlinux, S)

#endif /* _BTF_INFO_H */