SUBDIRS := ptrace ld_preload proc_mem dlopen_inject process_vm_writev

.PHONY: all clean test $(SUBDIRS)

all: $(SUBDIRS)

$(SUBDIRS):
	$(MAKE) -C $@

test: all
	$(MAKE) -C process_vm_writev test

clean:
	@set -e; for directory in $(SUBDIRS); do \
		$(MAKE) -C "$$directory" clean; \
	done
