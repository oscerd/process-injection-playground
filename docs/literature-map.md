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
| [Akamai PoCs](https://github.com/akamai/Linux-Process-Injection) and [dlinject](https://github.com/DavidBuchanan314/dlinject) | Demonstrate temporary code execution, with dlinject emphasizing recovery of modified state | `ptrace_restore` saves code, data, and registers, executes a benign marker, traps, restores, verifies, and resumes | Uses a dedicated patch slot and controlled child rather than arbitrary target instructions or a shell payload |
| [Jugaad: Run-time Thread Injection](https://magazine.hitb.org/wp-content/uploads/2021/05/HITB-Ezine-Issue-006.pdf) and [`ptrace(2)`](https://man7.org/linux/man-pages/man2/ptrace.2.html) | Treat thread selection and tracing as per-TID operations | `thread_hijack` enumerates a stable group, seizes every TID, redirects one worker, restores it, and detaches all TIDs | No thread creation race, stack payload, arbitrary PID, or persistent modification |
| [Akamai GOT overwrite PoC](https://github.com/akamai/Linux-Process-Injection) | Broadly overwrites candidate pointers in a writable GOT region | Parses `DT_JMPREL`, `DT_SYMTAB`, and `DT_STRTAB` to replace only the named `puts` jump slot | Adds a Full RELRO binary that asserts `EFAULT` and an unchanged slot |
| [Akamai stack-overwrite PoC](https://github.com/akamai/Linux-Process-Injection) and [linux-prinj](https://github.com/antifob/linux-prinj) | Finds a stack control-flow value and replaces it with a selected address | A dedicated frame publishes exactly one saved return slot and returns through an existing benign trampoline | No stack scan, spraying, ROP chain, or injected executable bytes |
| [linux-prinj hollowing PoC](https://github.com/antifob/linux-prinj/tree/main/04-hollowing) | Traces before `exec`, stops at the new image entry point, and overwrites code at RIP | `process_hollowing` uses a static controlled child and replaces 16 entry bytes with `exit(42)` | Described precisely as entry-point stomping rather than full ELF image replacement |
| [MITRE T1055.014](https://attack.mitre.org/techniques/T1055/014/) | Describes VDSO code or GOT redirection as part of a shared-object injection chain | `vdso_hijack` temporarily replaces one published VDSO function, asserts its return marker, and restores the bytes | No GOT modification, syscall chain, shared-object load, or persistent payload |
| [Linux kernel procfs memory implementation](https://github.com/torvalds/linux/blob/master/fs/proc/base.c) and [Akamai procfs PoC](https://github.com/akamai/Linux-Process-Injection) | Procfs memory writes can use forced remote access after ptrace authorization | Controlled read-only marker succeeds when kernel policy permits; non-dumpable victim asserts denial | No executable payload or register change in the automated cases |
| [`strace` internals](https://github.com/strace/strace/blob/master/doc/INTERNALS.md) | Launches or attaches to tracees with `PTRACE_TRACEME`, `PTRACE_ATTACH`, or `PTRACE_SEIZE` | Places `ptrace_traceme` beside `ptrace_seize` to compare opt-in launch and non-stopping attachment | Uses `PTRACE_SETREGS` only to select code already compiled into the victim |
| [Rory McNamara's procfs research](https://www.levelblue.com/blogs/spiderlabs-blog/linux-based-inter-process-code-injection-without-ptrace-2/) | Uses procfs memory access without making a ptrace syscall | `proc_mem` separates the `/proc/<pid>/mem` write from its register trigger | Documentation emphasizes that kernel ptrace access-mode checks still apply |
| [gaffe23/linux-inject](https://github.com/gaffe23/linux-inject) | Uses ptrace to arrange a remote shared-object load | `dlopen_inject` resolves a compatible target `dlopen`, executes a temporary call stub, and restores patched bytes and registers | Included library has a benign constructor and the victim is controlled |
| [Pure In-Memory (Shell)Code Injection in Linux Userland](https://deepsec.net/docs/Slides/2018/Pure_In-Memory_%28Shell%29Code_Injection_in_Linux_Userland_reenz0h.pdf) | Explores anonymous memory-backed staging and loading | `memfd_dlopen` loads a benign ELF object from a memfd in the current process | Keeps memory-backed loading separate from remote-process access |
| [dlinject](https://github.com/DavidBuchanan314/dlinject), [`memfd_create(2)`](https://man7.org/linux/man-pages/man2/memfd_create.2.html), and [`dlopen(3)`](https://man7.org/linux/man-pages/man3/dlopen.3.html) | Combine temporary remote loader execution, state restoration, and memory-backed files | `remote_memfd_dlopen` compares the same restored remote call for a disk path and an inherited memfd path | The parent pre-populates the memfd before launch; no arbitrary target, remote `memfd_create`, stack pivot, or reflective loader |
| GNU [`rtld-audit`](https://man7.org/linux/man-pages/man7/rtld-audit.7.html) documentation | Loader callbacks can observe and influence object and symbol binding | `ld_audit` reports object opens and the `puts` binding while returning the original address | Demonstrates observation, not binding replacement |

## Researched candidates

| Source | Candidate | What a safe repository version should prove | Status |
| --- | --- | --- | --- |
| [linux-prinj unused-code and code-cave PoCs](https://github.com/antifob/linux-prinj) | Reuse executable padding or unused mapped regions | Compare file identity, executable mappings, and recovery without targeting arbitrary programs | Research only; destructive semantics need stronger isolation |
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
