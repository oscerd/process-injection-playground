# Technique and Capability Matrix

This matrix separates lifecycle, memory-write primitive, execution trigger, and
recovery. Those dimensions are often conflated under the single term “process
injection,” which makes examples difficult to compare.

| Lab | Lifecycle | Writer or loader | Execution trigger | Architecture | Typical access requirement | Recovery |
| --- | --- | --- | --- | --- | --- | --- |
| `ptrace` | Existing process | `PTRACE_POKETEXT` | RIP changed with `PTRACE_SETREGS` | x86_64 | ptrace attach permitted | No; target state is overwritten |
| `ptrace_seize` | Existing child | `PTRACE_SEIZE` and `PTRACE_INTERRUPT` | None | Generally architecture-neutral | ptrace seize permitted | Tracee is detached without memory or register changes |
| `ptrace_traceme` with `SETREGS` | Opt-in child | Register set replaced with `PTRACE_SETREGS` | RIP selects an existing function | x86_64 | Child permits its parent with `PTRACE_TRACEME` | No restoration; selected benign function exits |
| `ptrace_traceme` with `POKEUSER` | Opt-in child | RIP and RSP user-area fields written individually | RIP selects an existing function | x86_64 | Child permits its parent with `PTRACE_TRACEME` | No restoration; selected benign function exits |
| `ptrace_restore` | Existing child | Dedicated code slot, data marker, and registers changed with ptrace | Temporary stub writes a marker and traps with `INT3` | x86_64 | Parent-child ptrace attach permitted | Code, marker, and registers are read back and verified before detach; child resumes normally |
| `thread_hijack` | Stable four-TID child | Every TID seized and stopped; one worker's code, data, and registers changed | Selected worker traps with `INT3` while siblings remain stopped | x86_64, POSIX threads | Ptrace seize permitted for every TID | Selected state restored and verified; every TID detached and resumed |
| `vdso_hijack` | Existing child | Eight bytes at `__vdso_gettimeofday` replaced with ptrace | Victim directly calls the modified VDSO function | x86_64 with named VDSO export | Parent-child ptrace attach permitted | Original VDSO bytes restored and normal function result asserted |
| `process_hollowing` entry stomp | Exec-stopped child | `PTRACE_POKETEXT` replaces bytes at initial RIP | Child continues at the modified entry point | x86_64 | Child requests tracing before `exec` | No restoration; benign replacement exits with marker 42 |
| `proc_mem` | Existing process | Write to `/proc/<pid>/mem` | RIP changed with `PTRACE_SETREGS` | x86_64 | procfs memory access and ptrace attach permitted | No; target state is overwritten |
| `proc_mem` read-only marker | Existing child | Positioned write to `/proc/<pid>/mem` | None | Generally architecture-neutral | Ptrace access-mode check permits opening the file; kernel permits force override | Not needed; victim observes benign data and exits |
| `proc_mem` non-dumpable | Existing child | Denied open of `/proc/<pid>/mem` | None | Generally architecture-neutral | Target opts out with `PR_SET_DUMPABLE=0` | Not needed; denial and unchanged marker are asserted |
| `process_vm_writev` marker | Existing child or permitted PID | `process_vm_writev` into writable data | None | Architecture-neutral | ptrace access-mode check permits the writer | Not needed; target observes a data marker and exits normally |
| `process_vm_writev` function pointer | Existing child | `process_vm_writev` into writable data | Target's next indirect call | Common Linux ABIs | ptrace access-mode check permits the writer | Not needed; target executes a pre-existing benign callback and exits normally |
| `process_vm_writev` non-dumpable | Existing child | Denied `process_vm_writev` attempt | None | Architecture-neutral | Target opts out with `PR_SET_DUMPABLE=0` | Not needed; denial and unchanged marker are asserted |
| `process_vm_writev` GOT, Partial RELRO | Existing child | Targeted write to the `puts` jump slot | Target's next `puts` call | ELF64, non-PIE example | Cross-process access permitted and jump slot remains writable | Not needed; target executes a pre-existing benign callback and exits normally |
| `process_vm_writev` GOT, Full RELRO | Existing child | Denied write to the read-only `puts` jump slot | None | ELF64, non-PIE example | Cross-process access permitted; mapping rejects the write | Not needed; `EFAULT` and unchanged binding are asserted |
| `process_vm_writev` stack return | Existing child | One saved return address in a live frame | Function epilogue consumes the changed slot with `ret` | x86_64 | ptrace access-mode check permits the writer | No restoration; existing benign callback exits |
| `dlopen_inject` | Existing process | `PTRACE_POKETEXT` | Temporary stub calls `dlopen` | x86_64, glibc | ptrace attach permitted; compatible libc | Patched instruction bytes and registers are restored; loaded library remains |
| `remote_memfd_dlopen`, disk | Existing child | Ptrace call stub, pathname storage, and dedicated stack | Remote `dlopen` call and ELF constructor | x86_64, glibc | Parent-child ptrace attach permitted; compatible libc | Patch, path, stack, and registers restored; file-backed library remains loaded |
| `remote_memfd_dlopen`, memfd | Controlled child inheriting a populated memfd | Same ptrace call stub with `/proc/self/fd/<fd>` | Remote `dlopen` call and ELF constructor | x86_64, glibc | Same ptrace access plus `memfd_create` availability | Patch, path, stack, and registers restored; memfd-backed library remains loaded |
| `ld_preload` | Controlled launch | ELF dynamic loader | Constructor and symbol resolution | Generally architecture-neutral | Control of the new process environment | Not applicable |
| `ld_audit` | Controlled launch | GNU runtime-linker audit API | Audit callbacks observe object loading and symbol binding | Common GNU/Linux ABIs | Control of the new process environment | Not applicable; original binding is preserved |
| `memfd_dlopen` | Current process | `memfd_create`, `/proc/self/fd`, and `dlopen` | Constructor and exported function | Generally architecture-neutral | Ability to create a memfd and load an ELF object | Handle is closed normally; mapping is removed by `dlclose` |

## ATT&CK mapping notes

- Ptrace-based modification maps directly to
  [T1055.008, Ptrace System Calls](https://attack.mitre.org/techniques/T1055/008/).
- The `vdso_hijack` lab isolates reversible code modification inside `[vdso]`.
  It maps to the VDSO surface in
  [T1055.014](https://attack.mitre.org/techniques/T1055/014/) but does not
  reproduce the broader GOT and shared-object loading chain described there.
- The `process_hollowing` lab is a Linux entry-point-stomping analogue built
  from ptrace operations. MITRE's
  [T1055.012, Process Hollowing](https://attack.mitre.org/techniques/T1055/012/)
  procedures and detection strategy are Windows-oriented, so do not claim an
  exact mapping without describing the Linux lifecycle.
- `/proc/<pid>/mem` manipulation maps to
  [T1055.009, Proc Memory](https://attack.mitre.org/techniques/T1055/009/).
- `process_vm_writev` does not currently have a dedicated ATT&CK sub-technique;
  use the parent [T1055](https://attack.mitre.org/techniques/T1055/) and describe
  the actual execution trigger when one is present.
- Linux `LD_PRELOAD` maps to
  [T1574.006, Dynamic Linker Hijacking](https://attack.mitre.org/techniques/T1574/006/).
- `LD_AUDIT` belongs to the same dynamic-linker environment family, but this
  repository's audit module only observes loader events and preserves the
  selected symbol address. It is instrumentation rather than hijacking.
- In-process loading from an anonymous file is closer to
  [T1620, Reflective Code Loading](https://attack.mitre.org/techniques/T1620/)
  than T1055 because no separate process is modified.
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

1. Clone races and signal/syscall interruption in a changing thread group.
2. AArch64 register and instruction-cache handling.
3. A target-created memfd comparison using a reversible remote syscall path.
