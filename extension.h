#ifndef _EXTENSION_H
#define _EXTENSION_H
#include <stdbool.h>

struct pginfo;
enum {
	PG_INCLUDE,	// Exntesion will keep the page
	PG_EXCLUDE,	// Exntesion will discard the page
	PG_UNDECID,	// Exntesion makes no decision
};
int run_extension_callback(unsigned long pfn, const void *pcache, const struct pginfo *i);
void init_extensions(void);
void cleanup_extensions(void);
bool add_extension_opts(char *opt);
bool extension_has_callback(void);

/*
 * Extensions are called for each PFN. This means that we are called for each
 * sub-page of a compound page. However, many extensions don't care to filter
 * sub-pages, and would prefer to return a decision for the whole compound page.
 * This macro can be used to define a callback which only calls the real
 * callback for non-tail pages. It caches the prior return value for the extent
 * the compound page range.
 *
 * If called for a tail page, it's possible (e.g. when re-filtering) that the
 * head page was not seen. In this case, the wrapper returns PG_UNDECID.
 */
#define EXTENSION_CALLBACK_COMPOUND_HEAD(real_callback)		\
	int extension_callback(unsigned long pfn,			\
			       const void *pcache,			\
			       const struct pginfo *i)			\
	{								\
		static int cached_decision = PG_UNDECID;		\
		static mdf_pfn_t cached_pfn_end = 0;			\
									\
		if (i->compound_head & 1) {				\
			/* Tail page! Return cached decision. */	\
			if (pfn < cached_pfn_end)			\
				return cached_decision;		\
									\
			static bool warned_missed_compound_head = false; \
			if (!warned_missed_compound_head) {		\
				ERRMSG("warning: saw compound tail but not corresponding head (PFN %lu).\n", pfn); \
				warned_missed_compound_head = true;	\
			}						\
			return PG_UNDECID;				\
			}						\
									\
		cached_pfn_end = pfn + (1 << i->compound_order);	\
		cached_decision = real_callback(pfn, pcache, i);	\
		return cached_decision;				\
		}
#endif /* _EXTENSION_H */

