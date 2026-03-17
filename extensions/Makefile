CC ?= gcc
CONTRIB_SO := amdgpu_filter.so

all: $(CONTRIB_SO)

amdgpu_filter.so: maple_tree.c

$(CONTRIB_SO): %.so: %.c
	$(CC) -O2 -g -fPIC -shared -Wl,-T,../makedumpfile.ld -o $@ $^

clean:
	rm -f $(CONTRIB_SO)