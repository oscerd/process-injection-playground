# Literature and PoC Coverage Map

This map turns papers, articles, and public proof-of-concept repositories into
specific playground coverage. The adaptations use controlled child processes,
benign callbacks, targeted writes, and asserted negative cases. They are not
line-for-line copies of offensive tooling.

## Implemented adaptations

| Source | Source mechanism | Playground adaptation | Deliberate difference |
| --- | --- | --- | --- |
| [Akamai Linux Process Injection research](https://www.akamai.com/blog/security-research/the-definitive-guide-to-linux-process-injection) and [PoCs](https://github.com/akamai/Linux-Process-Injection) | Separates ptrace, procfs, and `process_vm_writev` write primitives from register, stack, and GOT execution primitives | `ptrace`, `proc_mem`, `ptrace_traceme`, and the `process_vm_writev` marker, function-pointer, GOT, and stack-return victims | Controlled children and existing benign callbacks replace generic payload execution |
| [Akamai ptrace execution PoCs](https://github.com/akamai/Linux-Process-Injection) | Redirects RIP with either `PTRACE_SETREGS` or a `PTRACE_POKEUSER` write to the architecture user area | Runs both requests against the same opt-in child and the same benign destination | Also aligns RSP explicitly and asserts normal child completion |
| [Akamai GOT overwrite PoC](https://github.com/akamai/Linux-Process-Injection) | Broadly overwrites candidate pointers in a writable GOT region | Parses `DT_JMPREL`, `DT_SYMTAB`, and `DT_STRTAB` to replace only the named `puts` jump slot | Adds a Full RELRO binary that asserts `EFAULT` and an unchanged slot |
| [Akamai stack-overwrite PoC](https://github.com/akamai/Linux-Process-Injection) and [linux-prinj](https://github.com/antifob/linux-prinj) | Finds a stack control-flow value and replaces it with a selected address | A dedicated frame publishes exactly one saved return slot and returns through an existing benign trampoline | No stack scan, spraying, ROP chain, or injected executable bytes |
| [`strace` internals](https://github.com/strace/strace/blob/master/doc/INTERNALS.md) | Launches or attaches to tracees with `PTRACE_TRACEME`, `PTRACE_ATTACH`, or `PTRACE_SEIZE` | Places `ptrace_traceme` beside `ptrace_seize` to compare opt-in launch and non-stopping attachment | Uses `PTRACE_SETREGS` only to select code already compiled into the victim |
| [Rory McNamara's procfs research](https://www.levelblue.com/blogs/spiderlabs-blog/linux-based-inter-process-code-injection-without-ptrace-2/) | Uses procfs memory access without making a ptrace syscall | `proc_mem` separates the `/proc/<pid>/mem` write from its register trigger | Documentation emphasizes that kernel ptrace access-mode checks still apply |
| [gaffe23/linux-inject](https://github.com/gaffe23/linux-inject) | Uses ptrace to arrange a remote shared-object load | `dlopen_inject` resolves a compatible target `dlopen`, executes a temporary call stub, and restores patched bytes and registers | Included library has a benign constructor and the victim is controlled |
| [Pure In-Memory (Shell)Code Injection in Linux Userland](https://deepsec.net/docs/Slides/2018/Pure_In-Memory_%28Shell%29Code_Injection_in_Linux_Userland_reenz0h.pdf) | Explores anonymous memory-backed staging and loading | `memfd_dlopen` loads a benign ELF object from a memfd in the current process | Keeps memory-backed loading separate from remote-process access |
| GNU [`rtld-audit`](https://man7.org/linux/man-pages/man7/rtld-audit.7.html) documentation | Loader callbacks can observe and influence object and symbol binding | `ld_audit` reports object opens and the `puts` binding while returning the original address | Demonstrates observation, not binding replacement |

## Researched candidates

| Source | Candidate | What a safe repository version should prove | Status |
| --- | --- | --- | --- |
| [linux-prinj hollowing and unused-code PoCs](https://github.com/antifob/linux-prinj) | Replace executable contents or reuse code caves | Compare file identity, executable mappings, and recovery without targeting arbitrary programs | Research only; destructive semantics need stronger isolation |
| [David Buchanan's dlinject](https://github.com/DavidBuchanan314/dlinject) | `/proc/<pid>/mem`, stack pivot, remote `mmap`, and `dlopen` with restoration | Contrast on-disk and memfd-backed remote loading while proving register and stack recovery | Planned after common maps and ELF helpers exist |
| [Jugaad: Run-time Thread Injection](https://magazine.hitb.org/wp-content/uploads/2021/05/HITB-Ezine-Issue-006.pdf) | Thread-aware ptrace injection | Enumerate every controlled thread, stop consistently, redirect one, and resume without leaving siblings stopped | Planned multi-thread reliability lab |
| [MITRE T1055.014](https://attack.mitre.org/techniques/T1055/014/) | VDSO hijacking | Parse the controlled victim's VDSO and demonstrate a reversible, non-payload modification with explicit detection evidence | Research only; kernel and architecture variability are high |
| [Linux Process Injection via Seccomp Notify](https://www.outflank.nl/blog/2025/12/09/seccomp-notify-injection/) | Syscall user-notification manipulation | Use an intentionally installed listener and a controlled syscall argument, with no sandbox bypass claim | Planned experimental controlled-launch lab |
| [Elastic's GDB detection example](https://www.elastic.co/docs/reference/security/prebuilt-rules/rules/linux/credential_access_gdb_process_hooking) | Legitimate tooling used to call into a live process | Launch a dedicated child under GDB, load a benign library, and compare telemetry with direct ptrace | Planned optional lab because GDB is not a base dependency |

## Selection rules

A literature-derived example should be added when it contributes a new cell in
the technique matrix, not merely a different payload. Before implementation,
record:

1. The access primitive and exact kernel authorization path.
2. Whether the example writes data, control-flow state, or executable bytes.
3. The event that transfers execution.
4. Architecture, ABI, libc, compiler, and linker assumptions.
5. State that must be restored.
6. One observable denial or mitigation where practical.
7. How the repository version narrows the original PoC.

Examples that require hardcoded addresses, indiscriminate pointer overwrites,
or modifying arbitrary host processes should first be redesigned around a
purpose-built victim and a deterministic protocol.
