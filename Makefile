SUBDIRS := ptrace ptrace_seize ptrace_traceme ptrace_restore thread_hijack \
	vdso_hijack process_hollowing ld_preload ld_audit proc_mem \
	dlopen_inject remote_memfd_dlopen process_vm_writev memfd_dlopen

.PHONY: all clean test $(SUBDIRS)

all: $(SUBDIRS)

$(SUBDIRS):
	$(MAKE) -C $@

test: all
	$(MAKE) -C ptrace_seize test
	$(MAKE) -C ptrace_traceme test
	$(MAKE) -C ptrace_restore test
	$(MAKE) -C thread_hijack test
	$(MAKE) -C vdso_hijack test
	$(MAKE) -C process_hollowing test
	$(MAKE) -C ld_audit test
	$(MAKE) -C proc_mem test
	$(MAKE) -C remote_memfd_dlopen test
	$(MAKE) -C process_vm_writev test
	$(MAKE) -C memfd_dlopen test

clean:
	@set -e; for directory in $(SUBDIRS); do \
		$(MAKE) -C "$$directory" clean; \
	done
