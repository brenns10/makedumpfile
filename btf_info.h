#ifndef _BTF_INFO_H
#define _BTF_INFO_H
#include <stdint.h>

struct ktype_info {
	/********in******/
	char *modname;		// Set to search within the module, in case
				// name conflict of different modules
	char *struct_name;	// Search by struct name
	char *member_name;	// Search by member name
	/********out*****/
	uint32_t member_bit_offset;	// member offset in bits
	uint32_t member_bit_sz;	// member width in bits
	uint32_t member_size;	// member size in bytes
	uint32_t struct_size;	// struct size in bytes
};

bool check_ktypes_require_modname(char *modname, int *total);
bool register_ktype_section(char *start, char *stop);
bool init_kernel_btf(void);
bool init_module_btf(void);
void cleanup_btf(void);

#define QUATE(x) #x
#define INIT_MOD_STRUCT_MEMBER(MOD, S, M)			\
	struct ktype_info _##MOD##_##S##_##M = {		\
		QUATE(MOD), QUATE(S), QUATE(M), 0, 0, 0, 0	\
	};							\
	__attribute__((section(".init_ktypes"), used))		\
	struct ktype_info * _ptr_##MOD##_##S##_##M = &_##MOD##_##S##_##M

#define DECLARE_MOD_STRUCT_MEMBER(MOD, S, M) \
	extern struct ktype_info _##MOD##_##S##_##M

#define GET_MOD_STRUCT_MEMBER_MOFF(MOD, S, M)  (_##MOD##_##S##_##M.member_bit_offset)
#define GET_MOD_STRUCT_MEMBER_MSIZE(MOD, S, M) (_##MOD##_##S##_##M.member_size)
#define GET_MOD_STRUCT_MEMBER_SSIZE(MOD, S, M) (_##MOD##_##S##_##M.struct_size)

#define INIT_KERN_STRUCT_MEMBER(S, M) \
	INIT_MOD_STRUCT_MEMBER(vmlinux, S, M)

#define DECLARE_KERN_STRUCT_MEMBER(S, M) \
	DECLARE_MOD_STRUCT_MEMBER(vmlinux, S, M)

#define GET_KERN_STRUCT_MEMBER_MOFF(S, M)  GET_MOD_STRUCT_MEMBER_MOFF(vmlinux, S, M)
#define GET_KERN_STRUCT_MEMBER_MSIZE(S, M) GET_MOD_STRUCT_MEMBER_MSIZE(vmlinux, S, M)
#define GET_KERN_STRUCT_MEMBER_SSIZE(S, M) GET_MOD_STRUCT_MEMBER_SSIZE(vmlinux, S, M)

#define INIT_MOD_STRUCT(MOD, S)				\
	struct ktype_info _##MOD##_##S = {		\
		QUATE(MOD), QUATE(S), 0, 0, 0, 0, 0	\
	};						\
	__attribute__((section(".init_ktypes"), used))	\
	struct ktype_info * _ptr_##MOD##_##S = &_##MOD##_##S

#define GET_MOD_STRUCT_SSIZE(MOD, S) (_##MOD##_##S.struct_size)

#define INIT_KERN_STRUCT(S) \
	INIT_MOD_STRUCT(vmlinux, S)
#define GET_KERN_STRUCT_SSIZE(S) GET_MOD_STRUCT_SSIZE(vmlinux, S)

#endif /* _BTF_INFO_H */