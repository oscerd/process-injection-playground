# Linux Process Injection Playground

Small, readable Linux labs for studying remote-process memory access, execution
redirection, dynamic-loader interposition, detection opportunities, and the
kernel controls that constrain them.

## Responsible use

This project is provided strictly for education, defensive research, and
testing in environments you own or have explicit permission to assess. Do not
use these techniques to access, modify, disrupt, or monitor systems without
authorization, or for any activity that violates applicable law. You are
responsible for using the material safely and legally.

Prefer the included victim programs. Several low-level examples overwrite live
process state and are intentionally architecture-specific.

## Labs

| Lab | Lifecycle | Main primitive | Execution trigger | ATT&CK | Notes |
| --- | --- | --- | --- | --- | --- |
| [`ptrace`](ptrace/) | Running process | `PTRACE_POKETEXT` | `PTRACE_SETREGS` | [T1055.008](https://attack.mitre.org/techniques/T1055/008/) | x86_64 raw-code example |
| [`ptrace_seize`](ptrace_seize/) | Running child | `PTRACE_SEIZE` and `PTRACE_INTERRUPT` | None | Related to [T1055.008](https://attack.mitre.org/techniques/T1055/008/) | Process control without injection |
| [`ptrace_traceme`](ptrace_traceme/) | Opt-in child | `PTRACE_SETREGS` or `PTRACE_POKEUSER` | RIP redirected to existing code | [T1055.008](https://attack.mitre.org/techniques/T1055/008/) | x86_64, no code staging |
| [`ptrace_restore`](ptrace_restore/) | Running child | Temporary code, data, and register changes | `INT3` trap and resume | [T1055.008](https://attack.mitre.org/techniques/T1055/008/) | Asserts complete state restoration |
| [`thread_hijack`](thread_hijack/) | Multi-threaded child | Stop all TIDs, modify one worker | Selected worker traps through `INT3` | [T1055.008](https://attack.mitre.org/techniques/T1055/008/) | Per-thread control and group recovery |
| [`vdso_hijack`](vdso_hijack/) | Running child | Temporary `[vdso]` code replacement | Direct VDSO function call | [T1055.014](https://attack.mitre.org/techniques/T1055/014/) | Narrow reversible VDSO surface lab |
| [`process_hollowing`](process_hollowing/) | Exec-stopped child | `PTRACE_POKETEXT` at initial RIP | Replaced entry point | Related to T1055.008 | x86_64 entry-point stomping analogue |
| [`proc_mem`](proc_mem/) | Running process | `/proc/<pid>/mem` | Data-only or `PTRACE_SETREGS` | [T1055.009](https://attack.mitre.org/techniques/T1055/009/) | Includes read-only mapping and non-dumpable cases |
| [`process_vm_writev`](process_vm_writev/) | Running child | `process_vm_writev` | Marker, function pointer, GOT, or saved return address | [T1055](https://attack.mitre.org/techniques/T1055/) | Includes non-dumpable and Full RELRO denials |
| [`dlopen_inject`](dlopen_inject/) | Running process | ptrace memory writes | Remote `dlopen` call | T1055 / T1055.008 | x86_64, glibc, restores patched code |
| [`remote_memfd_dlopen`](remote_memfd_dlopen/) | Running child | Ptrace call stub plus inherited `memfd` | Remote `dlopen` and constructor | T1055 / T1055.008 | Compares disk and memory-backed mappings |
| [`ld_preload`](ld_preload/) | Process launch | Dynamic linker | Constructor and symbol interposition | [T1574.006](https://attack.mitre.org/techniques/T1574/006/) | Launch-time linker hijacking, not live injection |
| [`ld_audit`](ld_audit/) | Process launch | Runtime-linker audit API | Original binding is preserved | Related to [T1574.006](https://attack.mitre.org/techniques/T1574/006/) | Loader instrumentation, not injection |
| [`memfd_dlopen`](memfd_dlopen/) | Current process | `memfd_create` and `dlopen` | ELF constructor and exported function | [T1620](https://attack.mitre.org/techniques/T1620/) | Memory-backed staging, not remote injection |

See the [technique matrix](docs/technique-matrix.md) for prerequisites,
limitations, recovery behavior, and terminology.

## Quick start

Requirements:

- Linux and GCC
- GNU Make
- x86_64 for the existing raw-code and register examples
- ptrace permission for labs that attach to an existing PID

Build everything from the repository root:

```bash
make
```

Run the safe automated test:

```bash
make test
```

The tests cover ptrace seize and detach, opt-in register writes, state
restoration, multi-thread coordination, reversible VDSO modification,
exec-time entry-point stomping, procfs read-only memory behavior, loader
auditing, benign data and control-flow writes, a saved return-address redirect,
Partial versus Full RELRO, asserted non-dumpable denials, and local and remote
memory-backed shared-object loading. They normally need neither root nor a
change to `kernel.yama.ptrace_scope`.

Individual labs retain their own `Makefile` and README:

```bash
make -C ptrace
make -C process_vm_writev test
make clean
```

## Mental model

A Linux injection chain is easier to understand when separated into parts:

1. **Target access**: credentials, dumpability, capabilities, Yama, and other
   Linux Security Modules decide whether cross-process access is allowed.
2. **Memory write**: examples include ptrace requests, `/proc/<pid>/mem`, and
   `process_vm_writev`.
3. **Execution trigger**: examples include changing registers, patching an
   instruction, replacing a stack return address, or changing a function
   pointer.
4. **Recovery**: reliable tooling restores registers and overwritten bytes and
   accounts for signals and multiple threads.

A remote-memory write alone is not code execution. Likewise, `LD_PRELOAD` is a
controlled-launch linker feature rather than injection into an already-running
process. Keeping those distinctions visible is a core goal of this playground.

## Documentation

- [Technique and capability matrix](docs/technique-matrix.md)
- [Guided learning path](docs/lab-guide.md)
- [Annotated reading guide](docs/reading-guide.md)
- [Literature and PoC coverage map](docs/literature-map.md)
- [Observed use, reporting, and hollowing](docs/field-reporting.md)
- [Glossary](docs/glossary.md)
- [Mitigation matrix](docs/mitigation-matrix.md)
- [Detection lab](docs/detection-lab.md)
- [Curated references](docs/references.md)
- [Roadmap](docs/roadmap.md)

## Security controls worth testing

- Yama `kernel.yama.ptrace_scope`
- target credentials and `PR_SET_DUMPABLE`
- `CAP_SYS_PTRACE`
- SELinux and AppArmor policy
- PID and user namespaces
- writable versus executable mappings, PIE, NX, and RELRO
- static linking and alternate C libraries such as musl

The examples never change those controls automatically. In particular, do not
lower a host-wide `ptrace_scope` just to run a lab; use a controlled parent-child
target or an isolated disposable environment.

## Contributing

New labs should include:

- a controlled victim and benign default payload;
- supported architectures, kernel/library assumptions, and permissions;
- a one-command build and deterministic test where practical;
- expected observables and a blocked/negative case;
- cleanup or state-recovery behavior;
- accurate ATT&CK mapping and primary references.

The roadmap contains suggested additions including AArch64 support, advanced
multi-thread races, and seccomp user-notification research.

## License

Apache License 2.0. See [LICENSE.txt](LICENSE.txt).
