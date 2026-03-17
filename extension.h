#ifndef _EXTENSION_H
#define _EXTENSION_H

enum {
	PG_INCLUDE,	// Exntesion will keep the page
	PG_EXCLUDE,	// Exntesion will discard the page
	PG_UNDECID,	// Exntesion makes no decision
};
int run_extension_callback(unsigned long pfn, const void *pcache);
void init_extensions(void);
void cleanup_extensions(void);
#endif /* _EXTENSION_H */