# `memfd_create` and `dlopen`

This lab copies a benign shared object into an anonymous `memfd`, opens it
through `/proc/self/fd/<fd>`, and loads it with `dlopen`.

It demonstrates a **staging and loading primitive**, not remote-process
injection. The code is loaded into the process that created the memfd. A remote
injection chain could use the same staging idea only after separately obtaining
the ability to invoke syscalls and `dlopen` inside a target.

## Build and test

```bash
make
make test
```

Expected output includes:

```text
[*] Loading shared object through /proc/self/fd/...
[MEMFD_DEMO] Constructor executed from a memory-backed mapping
[MEMFD_DEMO] Exported function executed
[+] demo_entry returned 42
```

The source `.so` remains untouched. The loader copies its bytes into an
anonymous file descriptor and loads from that descriptor-backed path.

## What to observe

- `memfd_create`, followed by writes to the returned descriptor.
- An `openat` of `/proc/self/fd/<fd>` by the dynamic loader.
- An executable mapping whose name resembles
  `/memfd:process-injection-demo (deleted)` in `/proc/<pid>/maps`.
- Normal ELF relocation and constructor execution despite the lack of a
  persistent path for the loaded copy.

These behaviors also have legitimate uses, including JIT runtimes, sandboxing,
package systems, and temporary executable artifacts. Detection should correlate
the memory-backed mapping with process identity, provenance, and follow-on
behavior rather than alerting on `memfd_create` alone.

## ATT&CK mapping

[T1620, Reflective Code Loading](https://attack.mitre.org/techniques/T1620/)
includes anonymous files and in-process memory loading. This lab is closer to
that technique than T1055 because no separate process is modified.

## Limitations

- Linux only; `memfd_create` was added in Linux 3.17.
- The dynamic loader still handles a normal ELF shared object. This is not a
  custom reflective ELF mapper.
- Dependencies of the staged library are resolved normally and may still be
  loaded from disk.
- The memfd and its mappings remain visible through procfs and memory telemetry.

## References

- [`memfd_create(2)`](https://man7.org/linux/man-pages/man2/memfd_create.2.html)
- [`dlopen(3)`](https://man7.org/linux/man-pages/man3/dlopen.3.html)
- [MITRE ATT&CK T1620](https://attack.mitre.org/techniques/T1620/)
