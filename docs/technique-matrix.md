# Technique and Capability Matrix

This matrix separates lifecycle, memory-write primitive, execution trigger, and
recovery. Those dimensions are often conflated under the single term “process
injection,” which makes examples difficult to compare.

| Lab | Lifecycle | Writer or loader | Execution trigger | Architecture | Typical access requirement | Recovery |
| --- | --- | --- | --- | --- | --- | --- |
| `ptrace` | Existing process | `PTRACE_POKETEXT` | RIP changed with `PTRACE_SETREGS` | x86_64 | ptrace attach permitted | No; target state is overwritten |
| `proc_mem` | Existing process | Write to `/proc/<pid>/mem` | RIP changed with `PTRACE_SETREGS` | x86_64 | procfs memory access and ptrace attach permitted | No; target state is overwritten |
| `process_vm_writev` | Existing child or permitted PID | `process_vm_writev` into writable data | None in this lab | Architecture-neutral | ptrace access-mode check permits the writer | Not needed; target observes a data marker and exits normally |
| `dlopen_inject` | Existing process | `PTRACE_POKETEXT` | Temporary stub calls `dlopen` | x86_64, glibc | ptrace attach permitted; compatible libc | Patched instruction bytes and registers are restored; loaded library remains |
| `ld_preload` | Controlled launch | ELF dynamic loader | Constructor and symbol resolution | Generally architecture-neutral | Control of the new process environment | Not applicable |

## ATT&CK mapping notes

- Ptrace-based modification maps directly to
  [T1055.008, Ptrace System Calls](https://attack.mitre.org/techniques/T1055/008/).
- `/proc/<pid>/mem` manipulation maps to
  [T1055.009, Proc Memory](https://attack.mitre.org/techniques/T1055/009/).
- `process_vm_writev` does not currently have a dedicated ATT&CK sub-technique;
  use the parent [T1055](https://attack.mitre.org/techniques/T1055/) and describe
  the actual execution trigger when one is present.
- Linux `LD_PRELOAD` maps to
  [T1574.006, Dynamic Linker Hijacking](https://attack.mitre.org/techniques/T1574/006/).
- [T1055.001](https://attack.mitre.org/techniques/T1055/001/) describes Windows
  DLL injection and should not be used merely because a Linux lab loads a shared
  object.

## Access is shared across several interfaces

The labels “without ptrace” or “ptrace-less” can be misleading. Opening
`/proc/<pid>/mem` and calling `process_vm_writev` are both governed by kernel
ptrace access-mode checks even when the injector never invokes the `ptrace`
system call. Credentials, dumpability, capabilities, Yama, and other Linux
Security Modules can therefore affect all three approaches.

## Coverage gaps

The most useful next combinations are:

1. `process_vm_writev` plus a separately implemented execution trigger.
2. GOT/function-pointer overwrite with Partial versus Full RELRO targets.
3. Stack return-address overwrite against a controlled child.
4. Reliable save, trap, restore, and detach behavior for the raw-code labs.
5. Multi-thread targets and signal/syscall interruption.
6. AArch64 register and instruction-cache handling.
7. VDSO hijacking as an advanced Linux-specific lab.
