# Detection Lab

Every injection example should be useful from both sides: what changed in the
target, and what telemetry exposed the change.

Use the controlled `process_vm_writev` example first because it is deterministic
and does not redirect execution:

```bash
make -C process_vm_writev test
```

The test reports a skip when an outer sandbox returns `EPERM`. Check
`NoNewPrivs` and `Seccomp` in `/proc/self/status` when a direct parent-child
write is denied despite otherwise permissive credentials and Yama settings.

## Observe the syscall

If `strace` is available:

```bash
strace -f -e trace=process_vm_writev \
  ./process_vm_writev/inject --spawn ./process_vm_writev/victim-process/sample
```

The useful fields are the writer PID, target PID, remote address, requested
length, result length, and error code. A short or failed write matters: remote
iovecs can cross inaccessible pages and return a partial result.

For ptrace labs, observe the request sequence rather than only the syscall name:

```bash
strace -f -e trace=ptrace,wait4 \
  ./ptrace/inject <controlled-victim-pid>
```

Look for modification requests such as `PTRACE_POKETEXT`, `PTRACE_POKEDATA`,
`PTRACE_POKEUSER`, and `PTRACE_SETREGS`. Legitimate debuggers and crash handlers
are important false-positive sources, so detection should include process
ancestry, executable identity, target identity, and follow-on behavior.

## Audit example

The following host-wide audit rule requires administrative access. Review it
before use and remove it after the lab:

```bash
sudo auditctl -a always,exit -F arch=b64 \
  -S ptrace -S process_vm_writev -k process-injection-lab
sudo ausearch -k process-injection-lab
sudo auditctl -d always,exit -F arch=b64 \
  -S ptrace -S process_vm_writev -k process-injection-lab
```

Use the correct audit architecture on non-x86_64 systems. Production analytics
should be deployed through the host's normal audit-policy management rather
than ad hoc commands.

## Expected observables

| Primitive | High-signal behavior | Common legitimate sources |
| --- | --- | --- |
| ptrace | Attach followed by memory/register modification requests | GDB, debuggers, profilers, crash handlers |
| `/proc/<pid>/mem` | One process opens and writes another PID's `mem` file | Debuggers, diagnostics, specialized checkpoint tools |
| `process_vm_writev` | Source and target PIDs differ and the target is not an expected child/tool relationship | MPI/message-passing software, debuggers, compatibility layers |
| `memfd` plus `dlopen` | Writes to a memfd followed by `/proc/self/fd` access and an executable memory-backed ELF mapping | JIT runtimes, sandboxing, package systems, temporary executable artifacts |
| remote `dlopen` | ptrace activity followed by a new shared-object mapping | Debuggers, live instrumentation, observability agents |
| `LD_PRELOAD` | Loader variable plus an unusual early library mapping | Profilers, sanitizers, compatibility shims, test harnesses |

## Mitigation experiments

- Run the manual `process_vm_writev` mode from an unrelated process under Yama
  mode 1 and confirm that the kernel normally returns `EPERM`.
- Make the controlled victim non-dumpable with `PR_SET_DUMPABLE` and record how
  the result changes.
- Compare same-UID, different-UID, container PID namespace, and user namespace
  cases in disposable environments.
- For a future GOT lab, compile targets with Partial and Full RELRO and make the
  blocked write an asserted test outcome.
- Compare an ordinary file-backed `dlopen` with `memfd_dlopen` and record the
  differences in file, module-load, and memory-map telemetry.

Do not automatically weaken Yama, SELinux, AppArmor, or container isolation in
test scripts. A blocked lab is useful evidence, not a setup failure.
