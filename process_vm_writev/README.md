# `process_vm_writev` Remote-Memory Write

This lab demonstrates `process_vm_writev(2)`, one of the three main Linux
interfaces used to modify another process alongside `ptrace` writes and
`/proc/<pid>/mem`.

The example deliberately writes a benign 64-bit marker into a writable global
variable. It does not redirect execution. That distinction is important:
`process_vm_writev` is a **write primitive**, while a complete process-injection
chain also needs an execution trigger such as register, stack, instruction, or
function-pointer manipulation.

## Build and test

```bash
make
make test
```

The automated demonstration starts its own child process, obtains the address
of the child's marker through a pipe, writes the marker, and waits for the child
to confirm it. Because the target is a direct child, this normally works as an
unprivileged user when Yama uses its common `ptrace_scope=1` configuration.
If an outer container or sandbox seccomp policy denies cross-process memory
writes, `make test` reports the integration test as skipped instead of weakening
that policy.

Expected output includes:

```text
[*] Spawned controlled victim PID ...
[+] Wrote 0xc0defacecafebeef ...
Observed marker: 0xc0defacecafebeef
[+] Victim confirmed the remote write
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
- The destination must be writable; unlike `/proc/<pid>/mem` and some ptrace
  requests, this interface respects the target mapping's permissions.
- Access is still governed by a ptrace access-mode check and can fail with
  `EPERM` because of credentials, dumpability, capabilities, Yama, or another
  Linux Security Module.

## References

- [`process_vm_readv(2)` / `process_vm_writev(2)`](https://man7.org/linux/man-pages/man2/process_vm_readv.2.html)
- [Yama Linux Security Module](https://www.kernel.org/doc/html/latest/admin-guide/LSM/Yama.html)
- [The Definitive Guide to Linux Process Injection](https://www.akamai.com/blog/security-research/the-definitive-guide-to-linux-process-injection)
