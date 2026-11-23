# References

This list favors primary documentation and research that explains both the
mechanism and its defensive implications.

## Taxonomy and platform documentation

- [MITRE ATT&CK: Process Injection (T1055)](https://attack.mitre.org/techniques/T1055/)
- [MITRE ATT&CK: Ptrace System Calls (T1055.008)](https://attack.mitre.org/techniques/T1055/008/)
- [MITRE ATT&CK: Proc Memory (T1055.009)](https://attack.mitre.org/techniques/T1055/009/)
- [MITRE ATT&CK: VDSO Hijacking (T1055.014)](https://attack.mitre.org/techniques/T1055/014/)
- [MITRE ATT&CK: Dynamic Linker Hijacking (T1574.006)](https://attack.mitre.org/techniques/T1574/006/)
- [MITRE ATT&CK: Reflective Code Loading (T1620)](https://attack.mitre.org/techniques/T1620/)
- [`ptrace(2)`](https://man7.org/linux/man-pages/man2/ptrace.2.html)
- [`process_vm_readv(2)` and `process_vm_writev(2)`](https://man7.org/linux/man-pages/man2/process_vm_readv.2.html)
- [`PR_SET_DUMPABLE(2const)`](https://man7.org/linux/man-pages/man2/PR_SET_DUMPABLE.2const.html)
- [`/proc/<pid>/mem`](https://man7.org/linux/man-pages/man5/proc_pid_mem.5.html)
- [`memfd_create(2)`](https://man7.org/linux/man-pages/man2/memfd_create.2.html)
- [`dlopen(3)`](https://man7.org/linux/man-pages/man3/dlopen.3.html)
- [`rtld-audit(7)`](https://man7.org/linux/man-pages/man7/rtld-audit.7.html)
- [`ld.so(8)`](https://man7.org/linux/man-pages/man8/ld.so.8.html)
- [GNU C Library: Audit Module Loading](https://sourceware.org/glibc/manual/latest/html_node/Audit-Module-Loading.html)
- [GNU C Library: Audit API Callbacks](https://sourceware.org/glibc/manual/latest/html_node/Audit-API-Callbacks.html)
- [GNU C Library: Dynamic Linker Hardening](https://sourceware.org/glibc/manual/latest/html_node/Dynamic-Linker-Hardening.html)
- [System V ABI: ELF Object File Format](https://gabi.xinuos.com/elf.pdf)
- [Yama Linux Security Module](https://www.kernel.org/doc/html/latest/admin-guide/LSM/Yama.html)

For an ordered route through these materials and the matching repository labs,
see the [annotated reading guide](reading-guide.md).

## Technique research

- Ori David, [The Definitive Guide to Linux Process Injection](https://www.akamai.com/blog/security-research/the-definitive-guide-to-linux-process-injection), 2024.
- Akamai, [Linux-Process-Injection reference implementations](https://github.com/akamai/Linux-Process-Injection).
- Philippe Grégoire, [linux-prinj proof-of-concept series](https://github.com/antifob/linux-prinj).
- f0b, [Linux Process Injection series](https://blog.f0b.org/p/linux-process-injection-part2/), 2021.
- Rory McNamara, [Linux Based Inter-Process Code Injection Without Ptrace](https://www.levelblue.com/blogs/spiderlabs-blog/linux-based-inter-process-code-injection-without-ptrace-2/), 2017.
- rb, [Pure In-Memory (Shell)Code Injection in Linux Userland](https://deepsec.net/docs/Slides/2018/Pure_In-Memory_%28Shell%29Code_Injection_in_Linux_Userland_reenz0h.pdf), DeepSec 2018.
- Aseem Jakhar, [Jugaad: Run-time Thread Injection](https://magazine.hitb.org/wp-content/uploads/2021/05/HITB-Ezine-Issue-006.pdf), HITB Magazine / DEF CON 19.
- Julien Tinnes and Tavis Ormandy, [Playing with ptrace for fun and profit](https://repository.root-me.org/Reverse%20Engineering/x86/Unix/FR%20-%20SSTIC%2006%20-%20Playing%20with%20ptrace.pdf), SSTIC 2006.
- gaffe23, [linux-inject remote shared-object loader](https://github.com/gaffe23/linux-inject).
- David Buchanan, [dlinject](https://github.com/DavidBuchanan314/dlinject).
- Bishop Fox, [Tampering with Processes Using procfs](https://assets.bishopfox.com/prod-1437/Documents/Guides/2022-Q3-ToolTechGuide-Asminject-FINAL.pdf), 2022.
- Jary, [Detecting Shared Object Injection](https://virusbulletin.com/uploads/pdf/conference/vb2024/papers/Detecting-Shared-Object-injection.pdf), Virus Bulletin 2024.
- Kyle Avery, [Linux Process Injection via Seccomp Notify](https://www.outflank.nl/blog/2025/12/09/seccomp-notify-injection/), 2025.

## Detection and validation

- [Atomic Red Team T1055.009: Proc Memory](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1055.009/T1055.009.md)
- [Red Canary: Process Injection](https://redcanary.com/threat-detection-report/techniques/process-injection/)
- [Elastic: Linux Process Hooking via GDB](https://www.elastic.co/docs/reference/security/prebuilt-rules/rules/linux/credential_access_gdb_process_hooking)

## How to extend this list

For each new resource, record its year, platform, lifecycle (launch or live
process), write primitive, execution trigger, supported architecture, companion
code, and whether it includes detection or mitigation guidance. Avoid lists of
links with no explanation of what each source contributes.
