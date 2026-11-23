SUBDIRS := ptrace ptrace_seize ld_preload ld_audit proc_mem dlopen_inject \
	process_vm_writev memfd_dlopen

.PHONY: all clean test $(SUBDIRS)

all: $(SUBDIRS)

$(SUBDIRS):
	$(MAKE) -C $@

test: all
	$(MAKE) -C ptrace_seize test
	$(MAKE) -C ld_audit test
	$(MAKE) -C process_vm_writev test
	$(MAKE) -C memfd_dlopen test

clean:
	@set -e; for directory in $(SUBDIRS); do \
		$(MAKE) -C "$$directory" clean; \
	done
