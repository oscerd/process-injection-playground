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
- [`/proc/<pid>/mem`](https://man7.org/linux/man-pages/man5/proc_pid_mem.5.html)
- [`memfd_create(2)`](https://man7.org/linux/man-pages/man2/memfd_create.2.html)
- [`dlopen(3)`](https://man7.org/linux/man-pages/man3/dlopen.3.html)
- [Yama Linux Security Module](https://www.kernel.org/doc/html/latest/admin-guide/LSM/Yama.html)

## Technique research

- Ori David, [The Definitive Guide to Linux Process Injection](https://www.akamai.com/blog/security-research/the-definitive-guide-to-linux-process-injection), 2024.
- Akamai, [Linux-Process-Injection reference implementations](https://github.com/akamai/Linux-Process-Injection).
- Rory McNamara, [Linux Based Inter-Process Code Injection Without Ptrace](https://www.levelblue.com/blogs/spiderlabs-blog/linux-based-inter-process-code-injection-without-ptrace-2/), 2017.
- rb, [Pure In-Memory (Shell)Code Injection in Linux Userland](https://deepsec.net/docs/Slides/2018/Pure_In-Memory_%28Shell%29Code_Injection_in_Linux_Userland_reenz0h.pdf), DeepSec 2018.
- Aseem Jakhar, [Jugaad: Run-time Thread Injection](https://magazine.hitb.org/wp-content/uploads/2021/05/HITB-Ezine-Issue-006.pdf), HITB Magazine / DEF CON 19.
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
