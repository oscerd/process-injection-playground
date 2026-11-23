# Roadmap

The roadmap prioritizes reproducibility and defensive value before increasingly
fragile injection variants.

## Foundation

- [x] Add a repository-level build entry point.
- [x] Add a deterministic, benign automated lab.
- [x] Document lifecycle, write primitive, execution trigger, and recovery
      separately.
- [x] Add curated research and an initial detection lab.
- [ ] Replace duplicated `/proc/<pid>/maps`, PID parsing, and ptrace helpers with
      a small shared library.
- [ ] Standardize every lab on `make`, `make test`, and `make clean`.
- [ ] Add CI for GCC and Clang on x86_64.

## Reliability and negative cases

- [ ] Add save/trap/restore tests proving that targets remain alive.
- [x] Add a non-dumpable victim with an asserted denied-access result.
- [ ] Add denied-access modes for namespaces, seccomp, and LSM policy.
- [ ] Add multi-threaded and signal-interrupted victims.
- [x] Add a Partial versus Full RELRO executable comparison.
- [ ] Test PIE, NX, stripped binaries, static linking, glibc, and musl where
      relevant.
- [ ] Add sanitizers and fuzz tests for maps/ELF parsers.

## Technique coverage

- [x] Add the `process_vm_writev` memory-write primitive.
- [x] Compose `process_vm_writev` with a separately testable execution trigger.
- [x] Add a targeted GOT overwrite lab and Full RELRO blocked case.
- [x] Add an opt-in `PTRACE_TRACEME` register-redirection lab.
- [ ] Add a controlled stack return-address overwrite lab.
- [x] Add `PTRACE_SEIZE` and compare its stop behavior with `PTRACE_ATTACH`.
- [x] Add a non-modifying `LD_AUDIT` loader instrumentation lab.
- [x] Add in-process `memfd`-backed shared-object staging.
- [ ] Add an on-disk versus `memfd`-backed remote `dlopen` comparison.
- [ ] Add a VDSO hijacking lab mapped to T1055.014.
- [ ] Add a GDB-based example as a legitimate-tool comparison.
- [ ] Add seccomp user-notification as an experimental controlled-launch lab.

## Portability

- [ ] Introduce an architecture abstraction for register access and payloads.
- [ ] Port the core ptrace labs to AArch64.
- [ ] Run architecture-independent labs on both x86_64 and AArch64 CI runners.
