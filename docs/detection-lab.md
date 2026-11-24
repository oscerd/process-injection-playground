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

Compare that sequence with the non-modifying observer:

```bash
strace -f -e trace=ptrace,wait4 \
  ./ptrace_seize/observer --spawn ./ptrace_seize/victim-process/sample
```

The expected sequence is `PTRACE_SEIZE`, `PTRACE_INTERRUPT`, a ptrace stop, and
`PTRACE_DETACH`. No poke or register-write request should appear. This is a
useful reminder that a ptrace event is not, by itself, proof of injection.

Now compare the opt-in execution-redirection sequence:

```bash
strace -f -e trace=ptrace,wait4 \
  ./ptrace_traceme/redirector --spawn \
  ./ptrace_traceme/victim-process/sample
strace -f -e trace=ptrace,wait4 \
  ./ptrace_traceme/redirector --pokeuser --spawn \
  ./ptrace_traceme/victim-process/sample
```

The child first issues `PTRACE_TRACEME`. After its deliberate stop, the parent
uses `PTRACE_GETREGS`, a register-write primitive, and `PTRACE_CONT`. One run
replaces the register set with `PTRACE_SETREGS`; the other writes RIP and RSP
individually with `PTRACE_POKEUSER`. Neither run adds an executable mapping, but
RIP changes to an existing function in the victim.

The recovery-oriented sequence is longer:

```bash
strace -f -e trace=ptrace,wait4 \
  ./ptrace_restore/inject --spawn \
  ./ptrace_restore/victim-process/sample
```

It includes reads of the original state, code and register writes, continuation,
an `INT3` stop, restoration writes, verification reads, and detach. Restoration
reduces the lasting in-memory artifact, but it does not erase the earlier
ptrace sequence from syscall, audit, or endpoint telemetry.

Now compare a complete thread group:

```bash
strace -f -e trace=ptrace,wait4,tgkill \
  ./thread_hijack/injector --spawn \
  ./thread_hijack/victim-process/sample
```

The injector reads `/proc/<pid>/task`, sends `PTRACE_SEIZE` and
`PTRACE_INTERRUPT` to every TID, but sends code and register writes only to the
selected worker. A detector should retain the TID as well as the process ID so
that group coordination is not mistaken for four unrelated trace targets.

The negative remote-write case is also executable:

```bash
./process_vm_writev/inject --spawn \
  ./process_vm_writev/victim-process/non_dumpable
```

The victim calls `PR_SET_DUMPABLE=0`; the parent expects `EPERM` or `EACCES` and
also verifies that its marker was not changed.

For a mapping-permission comparison, run the two GOT victims:

```bash
./process_vm_writev/inject --spawn \
  ./process_vm_writev/victim-process/got_partial
./process_vm_writev/inject --spawn \
  ./process_vm_writev/victim-process/got_full
```

The first write changes only the resolved `puts` jump slot. The second reaches
the same stage but receives `EFAULT` because Full RELRO made that slot read-only.
If an outer access policy returns `EPERM` first, the test reports a skip because
that policy masks the mapping-permission experiment.

The saved-return-address example has the same remote-write syscall but a
different destination and trigger:

```bash
./process_vm_writev/inject --spawn \
  ./process_vm_writev/victim-process/stack_return
```

The remote address is inside the victim's writable stack. Execution changes
later when a normal function epilogue consumes that value with `ret`; there is
no new executable mapping or register-write syscall.

Compare remote-write behavior on a read-only data page:

```bash
./proc_mem/controlled_writer --spawn ./proc_mem/victim-process/read_only
./process_vm_writev/inject --spawn \
  ./process_vm_writev/victim-process/got_full
```

The destinations are different, but both are read-only mappings. The procfs
case can succeed through the kernel's configured force-override behavior, while
`process_vm_writev` returns `EFAULT`. Then run the procfs `non_dumpable` victim
to show that target authorization is still checked before mapping permissions.

Observe the exec-time entry replacement separately:

```bash
strace -f -e trace=ptrace,execve,wait4 \
  ./process_hollowing/hollower --spawn \
  ./process_hollowing/victim-process/sample
```

The high-signal sequence is `PTRACE_TRACEME`, `execve`, an exec-time stop,
`PTRACE_GETREGS`, `PTRACE_POKETEXT`, and continuation. A debugger can share much
of that lifecycle, so verify that the entry bytes diverge from the backing file.

Observe the VDSO destination separately:

```bash
strace -f -e trace=ptrace,wait4,kill \
  ./vdso_hijack/injector --spawn ./vdso_hijack/victim-process/sample
```

The write address belongs to `[vdso]`, not the main executable, heap, stack, or
a newly allocated mapping. The lab restores the original bytes, so a later
snapshot alone will not show the temporary change. Correlate the ptrace write,
signal-driven execution, trap, restoration write, and destination mapping.

Compare remote disk-backed and memfd-backed loader activity:

```bash
strace -f -e trace=ptrace,memfd_create,openat,wait4 \
  ./remote_memfd_dlopen/inject --mode disk \
  --library ./remote_memfd_dlopen/demo_lib.so \
  --spawn ./remote_memfd_dlopen/victim-process/sample
strace -f -e trace=ptrace,memfd_create,openat,wait4 \
  ./remote_memfd_dlopen/inject --mode memfd \
  --library ./remote_memfd_dlopen/demo_lib.so \
  --spawn ./remote_memfd_dlopen/victim-process/sample
```

Both cases have the same attach, patch, register-write, trap, restoration, and
detach sequence. Memfd mode additionally creates an anonymous file before the
child starts, opens `/proc/self/fd/<fd>` in the child, and leaves a mapping named
`memfd:remote-dlopen-demo (deleted)`. Disk mode leaves the ordinary pathname in
the mapping instead.

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
| restored ptrace execution | Writes and continuation followed by `SIGTRAP`, reverse writes, verification reads, and detach | Debuggers, hot patchers, live instrumentation |
| thread-group hijack | One tracer seizes every TID but modifies registers for one selected worker | Multi-thread debuggers, profilers, checkpoint tools |
| VDSO replacement | Ptrace write lands in `[vdso]` and is followed by execution at the modified function | Specialized debuggers and instrumentation |
| `/proc/<pid>/mem` | One process opens and writes another PID's `mem` file | Debuggers, diagnostics, specialized checkpoint tools |
| exec-time entry stomp | Trace-before-exec followed by writes at initial RIP and immediate changed behavior | Debuggers, instrumentation, test harnesses |
| `process_vm_writev` | Source and target PIDs differ and the target is not an expected child/tool relationship | MPI/message-passing software, debuggers, compatibility layers |
| GOT redirection | Remote write lands in a relocation slot and a later indirect call reaches an unusual executable address | Profilers, hot patching, compatibility and instrumentation tools |
| saved return-address redirection | Remote write lands on a writable stack and a later `ret` reaches an unusual executable address | Debuggers, checkpoint/restore tools, specialized instrumentation |
| `memfd` plus `dlopen` | Writes to a memfd followed by `/proc/self/fd` access and an executable memory-backed ELF mapping | JIT runtimes, sandboxing, package systems, temporary executable artifacts |
| remote `dlopen` | ptrace activity followed by a new file-backed or memfd-backed shared-object mapping | Debuggers, live instrumentation, observability agents |
| `LD_PRELOAD` | Loader variable plus an unusual early library mapping | Profilers, sanitizers, compatibility shims, test harnesses |
| `LD_AUDIT` | Loader audit variable, audit namespace mappings, and early audit callbacks | Linker diagnostics, tracing, profiling, and test tools |

## Mitigation experiments

- Run the manual `process_vm_writev` mode from an unrelated process under Yama
  mode 1 and confirm that the kernel normally returns `EPERM`.
- Compare the successful marker victim with the automated non-dumpable victim
  and record the denial, errno, and unchanged target state.
- Compare same-UID, different-UID, container PID namespace, and user namespace
  cases in disposable environments.
- Compare `got_partial` and `got_full`; verify the destination mapping
  permissions and record the successful redirect versus asserted `EFAULT`.
- Compare both `remote_memfd_dlopen` modes and record the differences in file,
  module-load, ptrace, and memory-map telemetry.

Do not automatically weaken Yama, SELinux, AppArmor, or container isolation in
test scripts. A blocked lab is useful evidence, not a setup failure.

For examples of how to distinguish confirmed incidents from PoCs and analytic
coverage, see [Observed Use, Reporting, and Process Hollowing](field-reporting.md).
