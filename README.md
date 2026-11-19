# Linux Process Injection Playground

Small, readable Linux labs for studying remote-process memory access, execution
redirection, dynamic-loader interposition, detection opportunities, and the
kernel controls that constrain them.

The examples are intended for systems you own or are explicitly authorized to
test. Prefer the included victim programs: several low-level examples overwrite
live process state and are intentionally architecture-specific.

## Labs

| Lab | Lifecycle | Main primitive | Execution trigger | ATT&CK | Notes |
| --- | --- | --- | --- | --- | --- |
| [`ptrace`](ptrace/) | Running process | `PTRACE_POKETEXT` | `PTRACE_SETREGS` | [T1055.008](https://attack.mitre.org/techniques/T1055/008/) | x86_64 raw-code example |
| [`proc_mem`](proc_mem/) | Running process | `/proc/<pid>/mem` | `PTRACE_SETREGS` | [T1055.009](https://attack.mitre.org/techniques/T1055/009/) | x86_64 procfs example |
| [`process_vm_writev`](process_vm_writev/) | Running child | `process_vm_writev` | Marker write or function-pointer redirection | [T1055](https://attack.mitre.org/techniques/T1055/) | Benign, rootless automated labs |
| [`dlopen_inject`](dlopen_inject/) | Running process | ptrace memory writes | Remote `dlopen` call | T1055 / T1055.008 | x86_64, glibc, restores patched code |
| [`ld_preload`](ld_preload/) | Process launch | Dynamic linker | Constructor and symbol interposition | [T1574.006](https://attack.mitre.org/techniques/T1574/006/) | Launch-time linker hijacking, not live injection |
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

The tests cover a benign marker write, controlled function-pointer redirection,
and memory-backed shared-object loading. They normally need neither root nor a
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

The roadmap contains suggested additions including GOT overwrite, VDSO
hijacking, `memfd`-backed library loading, AArch64 support, multi-thread recovery,
and seccomp user-notification research.

## License

Apache License 2.0. See [LICENSE.txt](LICENSE.txt).
