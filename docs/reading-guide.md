# Reading Guide

This path connects each lab to the platform documentation and research needed
to understand it. Read the primary documentation first, then use technique
articles to compare implementations and defensive observations.

## 1. Learn the Linux access model

Start here before comparing write primitives:

1. [`ptrace(2)`](https://man7.org/linux/man-pages/man2/ptrace.2.html), especially
   the request descriptions and ptrace access-mode algorithm.
2. [`credentials(7)`](https://man7.org/linux/man-pages/man7/credentials.7.html)
   for real, effective, saved, and filesystem IDs and capabilities.
3. [`PR_SET_DUMPABLE(2const)`](https://man7.org/linux/man-pages/man2/PR_SET_DUMPABLE.2const.html)
   for the target-side property exercised by the negative lab.
4. [Yama](https://www.kernel.org/doc/html/latest/admin-guide/LSM/Yama.html) for
   relationship-based restrictions beyond ordinary credential checks.
5. [The `/proc` filesystem](https://www.kernel.org/doc/html/latest/filesystems/proc.html)
   for process visibility and `/proc/<pid>/mem` access.

Then run `process_vm_writev` with the marker and non-dumpable victims. The
contrast makes the common access model visible without introducing executable
payloads.

## 2. Separate observation, writing, and execution

Read [`process_vm_readv(2)` and `process_vm_writev(2)`](https://man7.org/linux/man-pages/man2/process_vm_readv.2.html),
then compare these repository cases:

| Case | Access or observation | Remote write | Execution change |
| --- | --- | --- | --- |
| `ptrace_seize` | Yes | No | No |
| `ptrace_traceme` | Opt-in child tracing | No | RIP selects existing code |
| entry-point-stomping victim | Exec-time child tracing | Initial code bytes | Resume after the exec stop |
| marker victim | Yes | Data only | No |
| function-pointer victim | Yes | Control-flow data | Reuses an existing callback |
| GOT victim | Yes | One ELF jump slot | Reuses an existing callback |
| stack-return victim | Yes | One saved return address | Function epilogue executes an existing callback |
| raw ptrace lab | Yes | Instruction bytes | Changes RIP |
| `dlopen_inject` | Yes | Temporary call stub and path | Calls the target loader |

This vocabulary prevents a syscall alert, a memory write, and completed code
execution from being treated as equivalent events.

## 3. Learn ELF and the runtime linker

Use these in order:

1. [ELF Object File Format](https://gabi.xinuos.com/elf.pdf), especially program
   loading, dynamic sections, relocations, and symbol tables.
2. [`ld.so(8)`](https://man7.org/linux/man-pages/man8/ld.so.8.html) for search
   order, loader environment variables, and secure-execution behavior.
3. [`dlopen(3)`](https://man7.org/linux/man-pages/man3/dlopen.3.html) and
   [`dlsym(3)`](https://man7.org/linux/man-pages/man3/dlsym.3.html) for explicit
   runtime loading and symbol lookup.
4. [GNU C Library audit module loading](https://sourceware.org/glibc/manual/latest/html_node/Audit-Module-Loading.html)
   and [audit callbacks](https://sourceware.org/glibc/manual/latest/html_node/Audit-API-Callbacks.html)
   for `LD_AUDIT` namespaces and callback contracts.
5. [GNU C Library dynamic-linker hardening](https://sourceware.org/glibc/manual/latest/html_node/Dynamic-Linker-Hardening.html)
   for robustness trade-offs around late loading, interposition, and auditing.

Run `ld_preload`, `ld_audit`, and `memfd_dlopen` after reading this section.
Record which examples change resolution, merely observe it, or explicitly ask
the loader to add an object.

## 4. Compare implementation research

- Ori David, [The Definitive Guide to Linux Process Injection](https://www.akamai.com/blog/security-research/the-definitive-guide-to-linux-process-injection),
  pairs a broad technique survey with public reference implementations.
- Rory McNamara, [Linux Based Inter-Process Code Injection Without Ptrace](https://www.levelblue.com/blogs/spiderlabs-blog/linux-based-inter-process-code-injection-without-ptrace-2/),
  explores `/proc/<pid>/mem` and related interfaces while highlighting the
  difference between avoiding the ptrace syscall and avoiding ptrace policy.
- rb, [Pure In-Memory (Shell)Code Injection in Linux Userland](https://deepsec.net/docs/Slides/2018/Pure_In-Memory_%28Shell%29Code_Injection_in_Linux_Userland_reenz0h.pdf),
  covers memory-backed staging and user-space loading concepts.
- Aseem Jakhar, [Jugaad: Run-time Thread Injection](https://magazine.hitb.org/wp-content/uploads/2021/05/HITB-Ezine-Issue-006.pdf),
  provides historical context for ptrace-driven thread manipulation.
- Philippe Grégoire, [linux-prinj](https://github.com/antifob/linux-prinj),
  provides compact PoCs for stack spraying, hollowing, unused executable areas,
  and GOT/PLT redirection.
- David Buchanan, [dlinject](https://github.com/DavidBuchanan314/dlinject),
  demonstrates a restoration-oriented `/proc/<pid>/mem`, stack-pivot, and
  shared-object loading chain without invoking the ptrace syscall.

The [literature and PoC coverage map](literature-map.md) records which ideas are
already represented, which were deliberately narrowed, and which remain future
work.

The [field-reporting guide](field-reporting.md) separates confirmed telemetry,
named malware analysis, PoCs, and detection research, and explains the narrower
meaning of Linux process hollowing examples.

Treat implementation articles as environment-specific starting points. Check
their architecture, kernel, libc, compiler, and security-control assumptions
before reproducing a result.

## 5. Study detection and mitigations

1. Use the relevant [MITRE ATT&CK T1055](https://attack.mitre.org/techniques/T1055/)
   sub-technique page for vocabulary, procedures, and data sources.
2. Follow this repository's [detection lab](detection-lab.md) to collect syscall,
   ancestry, mapping, and loader evidence.
3. Use the [mitigation matrix](mitigation-matrix.md) to choose a control and an
   expected negative result.
4. Compare those results with detection engineering material from
   [Red Canary](https://redcanary.com/threat-detection-report/techniques/process-injection/),
   [Elastic](https://www.elastic.co/docs/reference/security/prebuilt-rules/rules/linux/credential_access_gdb_process_hooking),
   and [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1055.009/T1055.009.md).

The goal is a correlated story: who accessed which target, which state changed,
how execution followed, what was restored, and which policy allowed or denied
the chain.
