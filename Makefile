SUBDIRS := ptrace ld_preload proc_mem dlopen_inject process_vm_writev memfd_dlopen

.PHONY: all clean test $(SUBDIRS)

all: $(SUBDIRS)

$(SUBDIRS):
	$(MAKE) -C $@

test: all
	$(MAKE) -C process_vm_writev test
	$(MAKE) -C memfd_dlopen test

clean:
	@set -e; for directory in $(SUBDIRS); do \
		$(MAKE) -C "$$directory" clean; \
	done
