CC ?= gcc
CONTRIB_SO := amdgpu_filter.so

all: $(CONTRIB_SO)

$(CONTRIB_SO): %.so: %.c maple_tree.c
	$(CC) -O2 -g -fPIC -shared -Wl,-T,../makedumpfile.ld -o $@ $^

clean:
	rm -f $(CONTRIB_SO)