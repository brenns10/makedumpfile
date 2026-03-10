CC ?= gcc
CONTRIB_SO := amdgpu_filter.so userstack.so

all: $(CONTRIB_SO)

amdgpu_filter.so: maple_tree.c

userstack.so: maple_tree.c vma_rbtree.c

$(CONTRIB_SO): %.so: %.c
	$(CC) -O2 -g -fPIC -shared -Wl,-T,../makedumpfile.ld -o $@ $^

clean:
	rm -f $(CONTRIB_SO)
