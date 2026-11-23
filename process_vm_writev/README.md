# `process_vm_writev` Remote-Memory Write

This lab demonstrates `process_vm_writev(2)`, one of the three main Linux
interfaces used to modify another process alongside `ptrace` writes and
`/proc/<pid>/mem`.

The directory contains six controlled victims:

1. `sample` receives a benign 64-bit marker in a writable global variable. It
   demonstrates the remote-memory write primitive without redirecting execution.
2. `function_pointer` receives the address of a benign callback already present
   in its executable. Replacing its writable function-pointer slot redirects the
   next indirect call without injecting new code.
3. `non_dumpable` calls `prctl(PR_SET_DUMPABLE, 0)` before requesting a write.
   The test passes only when the kernel rejects the write with an access error
   and the victim confirms that its protected marker remains unchanged.
4. `got_partial` locates only its `puts` jump slot by parsing the in-memory ELF
   dynamic table. With Partial RELRO, `process_vm_writev` replaces that writable
   slot with an existing benign callback.
5. `got_full` uses the same source compiled with Full RELRO and immediate
   binding. The expected `EFAULT` result and unchanged jump slot are both
   asserted.
6. `stack_return` identifies one live saved return-address slot in a dedicated
   frame. The parent replaces it with an existing benign trampoline, and the
   victim triggers the redirect by returning normally.

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
[GOT REDIRECTED] Existing benign callback executed
[FULL RELRO] puts jump slot remained unchanged
[+] Kernel rejected the write with Bad address as expected
[STACK REDIRECTED] Saved return address selected a benign callback
[+] Victim confirmed the requested behavior
```

The GOT pair is an ELF64, non-PIE teaching example. It intentionally targets one
named relocation rather than scanning or overwriting a broad range of pointers.
The in-memory parser demonstrates how `DT_JMPREL`, `DT_SYMTAB`, and `DT_STRTAB`
connect a symbol name to its jump slot.

The stack example is x86_64-specific and compiled with a frame pointer so the
saved return slot has a deterministic contract. A small existing trampoline
preserves the System V stack alignment before calling the benign callback. It
does not stage executable bytes or scan arbitrary stack contents.

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
- The Partial RELRO victim changes one dynamic-linker control-flow slot. The
  Full RELRO victim turns the same request into an executable negative test.
- The stack victim changes a control-flow value consumed by `ret`, illustrating
  a different execution trigger from an indirect function call or GOT lookup.
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
- [Akamai Linux Process Injection PoCs](https://github.com/akamai/Linux-Process-Injection)
- [System V ABI: ELF Object File Format](https://gabi.xinuos.com/elf.pdf)
