# Mitigation Matrix

No single control blocks every example because the repository covers different
lifecycles and primitives. Use this matrix to choose negative tests and to avoid
overstating what a mitigation protects.

| Control | Ptrace operations | `/proc/<pid>/mem` | `process_vm_writev` | Loader environment | `memfd_dlopen` | Main trade-off |
| --- | --- | --- | --- | --- | --- | --- |
| Credentials and dumpability | Strong effect | Strong effect | Strong effect | Little direct effect | None for self-load | Restricts debugging and crash collection |
| Yama `ptrace_scope` | Strong effect | Strong effect through ptrace access checks | Strong effect through ptrace access checks | None | None | Higher modes limit developer and support workflows |
| `CAP_SYS_PTRACE` management | Controls privileged override | Controls privileged override | Controls privileged override | None | None | Broad capability should be tightly scoped |
| SELinux or AppArmor | Can restrict | Can restrict procfs access | Can restrict | Can restrict loader/module access | Can restrict executable mappings and procfs paths | Requires policy design and maintenance |
| PID and user namespaces | Narrows visible or reachable targets | Narrows procfs view | Narrows reachable targets | Mostly per-process | Mostly per-process | Isolation depends on namespace and mount configuration |
| Seccomp | Can deny ptrace requests | Can restrict required file syscalls | Can deny `process_vm_writev` | Applied after process startup in many designs | Can deny `memfd_create` or related operations | Filters must account for legitimate tooling |
| `PR_SET_DUMPABLE=0` | Blocks ordinary attach | Restricts procfs memory access | Blocks ordinary remote access | None | None for self-load | Impacts diagnostics and core dumps |
| Secure-execution mode | None | None | None | Strips or restricts variables such as `LD_PRELOAD` and `LD_AUDIT` | None for explicit self-load | Primarily applies to privileged execution transitions |
| Static linking | None | None | None | Removes normal dynamic-loader interposition | Prevents loading into a fully static target unless it embeds loader support | Larger binaries and reduced runtime flexibility |
| Full RELRO | Does not block arbitrary ptrace writes | Does not necessarily block procfs writes | Blocks writes that respect mapping permissions | None | None | Protects relocation tables, not all control-flow data |
| NX and W^X | Complicates direct code execution | Complicates direct code execution | Prevents execution from non-executable data pages | Loader maps executable segments normally | Loader maps executable ELF segments normally | Does not stop reuse of already-executable code |

## Detection remains necessary

Preventive controls often preserve exceptions for debuggers, observability
agents, crash handlers, JIT runtimes, and compatibility tools. Detection should
therefore correlate:

- source and target process identities;
- ancestry and expected debugging relationships;
- ptrace request types;
- remote write addresses and mapping permissions;
- new executable or shared-object mappings;
- loader environment variables;
- behavior that follows the memory or control-flow change.

The non-dumpable victim asserts an access-policy denial. The Full RELRO victim
asserts a mapping-permission failure after access is granted. Future labs should
add asserted denials for seccomp and namespace boundaries.
