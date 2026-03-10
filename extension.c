#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <unistd.h>
#include "kallsyms.h"
#include "btf_info.h"

/* Extension .so handlers array */
static void **handlers = NULL;
static int handlers_len = 0;
static int handlers_cap = 0;

/* Extension option array */
static char **extension_opts = NULL;
static int extension_opts_len = 0;
static int extension_opts_cap = 0;

static const char *dirs[] = {
	"/usr/lib64/makedumpfile/extensions/",
	"./extensions/",
};

void add_extension_opts(char *opt)
{
	if (!add_to_arr((void ***)&extension_opts, &extension_opts_len,
			&extension_opts_cap, opt))
		/*
		 * If fail, print error info and skip the extension.
		*/
		 fprintf(stderr, "%s: Fail to add extension %s\n", __func__, opt);
}

static bool init_kallsyms_btf(void)
{
	int count;
	bool ret = false;
	/* We will load module's btf/kallsyms on demand */
	bool init_ksyms_module = false;
	bool init_ktypes_module = false;

	if (check_ksyms_require_modname("vmlinux", &count)) {
		if (!init_kernel_kallsyms())
			goto out;
		if (count >= 2)
			init_ksyms_module = true;
	}
	if (check_ktypes_require_modname("vmlinux", &count)) {
		if (!init_kernel_btf())
			goto out;
		if (count >= 2)
			init_ktypes_module = true;
	}
	if (init_ksyms_module && !init_module_kallsyms())
		goto out;
	if (init_ktypes_module && !init_module_btf())
		goto out;	
	ret = true;
out:
	return ret;
}

static void load_extensions(void)
{
	char path[512];
	int len, i, j;
	void *handle;

	for (i = 0; i < extension_opts_len; i++) {
		handle = NULL;
		if (!extension_opts[i])
			continue;
		if ((len = strlen(extension_opts[i])) <= 3 ||
		    (strcmp(extension_opts[i] + len - 3, ".so") != 0)) {
			fprintf(stderr, "%s: Skip invalid extension: %s\n",
				__func__, extension_opts[i]);
			continue;
		}

		if (extension_opts[i][0] == '/') {
			/* Path & filename */
			snprintf(path, sizeof(path), "%s", extension_opts[i]);
			handle = dlopen(path, RTLD_NOW);
			if (!handle) {
				fprintf(stderr, "%s: Failed to load %s\n",
					__func__, dlerror());
				continue;
			}
		} else {
			/* Only filename */
			for (j = 0; j < sizeof(dirs) / sizeof(char *); j++) {
				snprintf(path, sizeof(path), "%s", dirs[j]);
				len = strlen(path);
				snprintf(path + len, sizeof(path) - len, "%s",
					extension_opts[i]);
				if (access(path, F_OK) == 0) {
					handle = dlopen(path, RTLD_NOW);
					if (handle)
						break;
					else
						fprintf(stderr, "%s: Failed to load %s\n",
							__func__, dlerror());					
				}
			}
			if (!handle && j >= sizeof(dirs) / sizeof(char *)) {
				fprintf(stderr, "%s: Not found %s\n",
					__func__, extension_opts[i]);
				continue;				
			}
		}

		if (dlsym(handle, "entry") == NULL) {
			fprintf(stderr, "%s: Skip extension %s: No entry()\n",
				__func__, path);
			dlclose(handle);
			continue;
		}

		if (!add_to_arr(&handlers, &handlers_len, &handlers_cap, handle)) {
			fprintf(stderr, "%s: Failed to load %s\n", __func__,
				extension_opts[i]);
			dlclose(handle);
			continue;
		}
		printf("Loaded extension: %s\n", path);
	}
}

static bool register_extension_sections(void)
{
	char *start, *stop;
	int i;
	bool ret = false;

	for (i = 0; i < handlers_len; i++) {
		start = dlsym(handlers[i], "__start_init_ksyms");
		stop = dlsym(handlers[i], "__stop_init_ksyms");
		if (!register_ksym_section(start, stop))
			goto out;

		start = dlsym(handlers[i], "__start_init_ktypes");
		stop = dlsym(handlers[i], "__stop_init_ktypes");
		if (!register_ktype_section(start, stop))
			goto out;
	}
	ret = true;
out:
	return ret;
}

void cleanup_extensions(void)
{
	for (int i = 0; i < handlers_len; i++) {
		dlclose(handlers[i]);
	}
	if (handlers)
		free(handlers);
	if (extension_opts)
		free(extension_opts);
	cleanup_kallsyms();
	cleanup_btf();
}

void init_extensions(void)
{
	/* Entry of extension execution */
	void (*entry)(void);

	load_extensions();
	if (!register_extension_sections())
		goto fail;
	if (!init_kallsyms_btf()) 
		goto fail;
	for (int i = 0; i < handlers_len; i++) {
		entry = dlsym(handlers[i], "entry");
		entry();
	}
	return;
fail:
	fprintf(stderr, "%s: fail & skip all extensions\n", __func__);
	cleanup_extensions();
}