# Guided Lab Path

The examples are most useful when treated as small mechanisms that can be
combined, rather than as a list ordered by perceived stealth or complexity.

## Before starting

Collect the environment facts that affect the outcome:

```bash
uname -m
uname -r
cat /proc/sys/kernel/yama/ptrace_scope
grep -E '^(NoNewPrivs|Seccomp|CapEff):' /proc/self/status
```

Build and run the deterministic suite:

```bash
make clean all
make test
```

The automated tests only target child processes created by the test runner.
They do not lower Yama settings, grant capabilities, or modify host security
policy.

## Stage 1: Loader behavior

Start with mechanisms that act during a controlled process launch:

1. `ld_preload`: observe constructors and ordinary symbol interposition.
2. `ld_audit`: observe loader callbacks while preserving the original symbol
   binding.

Questions to answer:

- Which environment variable activates each mechanism?
- Which library namespace contains the module?
- Does the victim's behavior change?
- What changes under secure-execution mode or static linking?

## Stage 2: Cross-process access

Use the `process_vm_writev` victims in this order:

1. `sample`: write data without changing control flow.
2. `non_dumpable`: confirm that `PR_SET_DUMPABLE=0` blocks the same parent.
3. `function_pointer`: change a writable control-flow value without staging new
   executable bytes.
4. `got_partial`: parse the dynamic table and replace one writable jump slot.
5. `got_full`: repeat the exact target selection and assert that the read-only
   mapping rejects the write.
6. `stack_return`: replace a saved return address in a known live frame and
   compare the `ret` trigger with the earlier indirect-call triggers.

This separates access policy, remote writing, and execution redirection into
independently observable steps.

## Stage 3: Ptrace control

Run `ptrace_seize`, then `ptrace_traceme`, before the raw ptrace injector. The
pair demonstrates that:

- establishing a trace relationship does not itself require modifying state;
- `PTRACE_SEIZE` and `PTRACE_INTERRUPT` separate attachment from stopping;
- ptrace acts on individual threads, which matters for multi-threaded targets;
- detection should inspect request types and sequences.
- a child can opt into tracing, after which `PTRACE_SETREGS` can redirect RIP
  without staging new code.
- `PTRACE_POKEUSER` can produce the same final RIP and RSP values through
  separate architecture-specific user-area writes.

Run `ptrace_restore` next. It adds a temporary code stub and register redirect,
regains control through `INT3`, restores code, data, and registers, and proves
that the child resumes. Then compare it with the legacy `ptrace` example, which
adds memory writes and register changes without recovery.

## Stage 4: Other write and execution combinations

- Start with the controlled `proc_mem` pair. It demonstrates a write through a
  read-only mapping and then an access denial from `PR_SET_DUMPABLE=0`.
- The legacy `proc_mem` example writes through `/proc/<pid>/mem`, then redirects
  RIP with ptrace. It is manual and intentionally excluded from `make test`.
- `process_hollowing` stops a child immediately after `exec` and replaces its
  first instructions with a benign exit marker. Compare the precise term
  "entry-point stomping" with full image replacement.
- `dlopen_inject` writes a temporary call stub, invokes `dlopen`, and restores
  the overwritten instruction bytes and registers.

For each example, identify:

1. How target access is authorized.
2. Where bytes are written.
3. Which event transfers execution.
4. Which state is restored.
5. Which artifacts remain after the example finishes.

## Stage 5: Memory-backed loading

`memfd_dlopen` copies an ELF shared object into an anonymous file and loads it
inside the current process. Compare its memory maps and file activity with the
ordinary file-backed `dlopen` path.

Then run `remote_memfd_dlopen` in both modes. It uses the same ptrace-driven
remote `dlopen` call for an ordinary path and an inherited memfd path. The
parent creates and populates the memfd before the controlled child starts, so
the lab demonstrates remote loading from an inherited descriptor rather than
remote `memfd_create` inside an arbitrary process.

## Observe and deny

Where available, trace a lab with a narrow syscall filter:

```bash
strace -f -e trace=ptrace,process_vm_writev,memfd_create,openat \
  make test
```

A useful lab includes both a successful mechanism and a denied case. Preserve
the denial as evidence. Do not turn off a security control merely to make every
example succeed.

## Suggested exercises

- Add a multi-threaded victim and record which thread IDs are traced.
- Add `PR_SET_DUMPABLE=0` to another victim and compare the error path.
- Compare PIE and non-PIE target addresses.
- Inspect Partial and Full RELRO binaries with `readelf`.
- Capture `/proc/<pid>/maps` for both `remote_memfd_dlopen` modes and compare
  named and `memfd:` mappings.
- Write a detector that distinguishes `PTRACE_SEIZE` observation from later
  memory or register modification.
