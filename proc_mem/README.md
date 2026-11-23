# `/proc/<pid>/mem` Remote Writes

This directory now contains two forms of the procfs memory technique:

- a deterministic controlled-child lab with benign data and an asserted denial;
- the original manual x86_64 raw-code example, retained for comparison but not
  executed by the automated test suite.

## Controlled read-only mapping lab

The safe lab separates two controls that are often conflated:

1. `read_only` creates an anonymous page, stores a zero marker, and changes the
   mapping to `PROT_READ` with `mprotect`.
2. Its parent opens `/proc/<pid>/mem` and uses `pwrite` at the announced address.
3. On kernels that permit the procfs force override, the marker changes despite
   the target mapping being read-only.
4. `non_dumpable` repeats the setup after `PR_SET_DUMPABLE=0`; opening its memory
   file must fail with `EACCES` or `EPERM`, and the victim confirms that the
   marker remains unchanged.

Build and run both cases:

```bash
make
make test
```

Expected output includes:

```text
[+] Wrote 8 bytes through /proc/.../mem ...
[VICTIM] Marker changed despite the read-only mapping
open /proc/.../mem: Permission denied
[+] Kernel denied non-dumpable procfs memory access as expected
```

The test creates its own direct children. It does not require root under common
Yama mode 1 configurations and never changes host security policy. A kernel,
container, or LSM policy that disables the procfs memory override produces a
skip for the positive case instead of weakening that policy.

## Why this differs from `process_vm_writev`

| Property | `/proc/<pid>/mem` controlled lab | `process_vm_writev` lab |
| --- | --- | --- |
| Cross-process authorization | Ptrace access-mode check while opening the memory file | Ptrace access-mode check on the syscall |
| Read-only target mapping | May be overridden by procfs forced access policy | Write fails with `EFAULT` |
| Data transport | `open` plus positioned file write | Remote and local iovec arrays |
| Execution trigger | None in the controlled case | Separate function-pointer, GOT, and stack examples |

Current Linux kernel source makes the forced behavior configurable through the
procfs memory implementation. The observable result is therefore more useful
than assuming that every kernel behaves identically.

## Detection notes

- Correlate a process opening another PID's `mem` file with later positioned
  writes.
- Record source and target ancestry, credentials, namespaces, and dumpability.
- A write into a mapping shown as read-only is a particularly useful signal.
- Debuggers, checkpoint/restore systems, and diagnostics are legitimate users.
- No `PTRACE_ATTACH` syscall is needed when the parent-child access relationship
  already permits opening the file.

## Original raw-code example

The `inject` binary is the original manual demonstration. It attaches to a PID,
overwrites bytes at the start of an executable mapping, changes RIP, and does
not restore the target. Its payload launches a shell.

It is intentionally excluded from `make test`. Use it only in an isolated
disposable environment against the included legacy victim. The controlled lab
is the recommended default because it is deterministic, benign, and asserts
both success and denial behavior.

## References

- [`/proc/<pid>/mem`](https://man7.org/linux/man-pages/man5/proc_pid_mem.5.html)
- [Linux kernel `fs/proc/base.c`](https://github.com/torvalds/linux/blob/master/fs/proc/base.c)
- [Linux kernel procfs documentation](https://www.kernel.org/doc/html/latest/filesystems/proc.html)
- [Akamai Linux Process Injection PoCs](https://github.com/akamai/Linux-Process-Injection)
- [Linux inter-process injection without a ptrace syscall](https://www.levelblue.com/blogs/spiderlabs-blog/linux-based-inter-process-code-injection-without-ptrace-2/)
