# `process_vm_writev` Remote-Memory Write

This lab demonstrates `process_vm_writev(2)`, one of the three main Linux
interfaces used to modify another process alongside `ptrace` writes and
`/proc/<pid>/mem`.

The directory contains three controlled victims:

1. `sample` receives a benign 64-bit marker in a writable global variable. It
   demonstrates the remote-memory write primitive without redirecting execution.
2. `function_pointer` receives the address of a benign callback already present
   in its executable. Replacing its writable function-pointer slot redirects the
   next indirect call without injecting new code.
3. `non_dumpable` calls `prctl(PR_SET_DUMPABLE, 0)` before requesting a write.
   The test passes only when the kernel rejects the write with an access error
   and the victim confirms that its protected marker remains unchanged.

This distinction matters: `process_vm_writev` is a **write primitive**. A full
process-injection chain also needs an execution trigger such as register, stack,
instruction, or function-pointer manipulation, plus actual code staging if the
desired code is not already mapped in the target.

## Build and test

```bash
make
make test
```

The automated demonstrations start their own child processes. Each victim sends
a bounded write request through a pipe, including the target address and the
bytes expected by that particular lab. Because the target is a direct child,
this normally works as an unprivileged user when Yama uses its common
`ptrace_scope=1` configuration.
If an outer container or sandbox seccomp policy denies cross-process memory
writes, `make test` reports the integration test as skipped instead of weakening
that policy.

Expected output includes:

```text
[*] Spawned controlled victim PID ...
[+] Wrote 8 bytes ...
Observed marker: 0xc0defacecafebeef
[REDIRECTED] Benign function-pointer callback executed
Protected marker remained unchanged
[+] Kernel denied the write as expected
[+] Victim confirmed that the marker remained unchanged
[+] Victim confirmed the requested behavior
```

## Manual mode

Start the victim and note the PID and marker address:

```bash
./victim-process/sample
```

Then, where the kernel's ptrace access checks permit it:

```bash
./inject <pid> <marker-address> [value]
```

On systems with Yama mode 1, an unrelated injector is normally denied even
when both processes use the same UID. Prefer `--spawn` for the safe lab rather
than weakening the host's policy.

## What to observe

- The `process_vm_writev` system call and its source and target PIDs.
- No `PTRACE_ATTACH` request is needed for this example.
- The function-pointer victim changes control flow but stages no new executable
  bytes; both possible callback functions were compiled into the target.
- The destination must be writable; unlike `/proc/<pid>/mem` and some ptrace
  requests, this interface respects the target mapping's permissions.
- Access is still governed by a ptrace access-mode check and can fail with
  `EPERM` because of credentials, dumpability, capabilities, Yama, or another
  Linux Security Module.
- The non-dumpable case converts one of those failure modes into an asserted
  mitigation test.

## References

- [`process_vm_readv(2)` / `process_vm_writev(2)`](https://man7.org/linux/man-pages/man2/process_vm_readv.2.html)
- [Yama Linux Security Module](https://www.kernel.org/doc/html/latest/admin-guide/LSM/Yama.html)
- [`PR_SET_DUMPABLE`](https://man7.org/linux/man-pages/man2/PR_SET_DUMPABLE.2const.html)
- [The Definitive Guide to Linux Process Injection](https://www.akamai.com/blog/security-research/the-definitive-guide-to-linux-process-injection)
