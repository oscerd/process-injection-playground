# `PTRACE_TRACEME` Execution Redirection

This x86_64 lab demonstrates the opt-in ptrace lifecycle used when a debugger
launches a program, then composes it with a benign execution trigger:

1. The controlled child calls `PTRACE_TRACEME`.
2. The child reports the address of an existing benign function and stops.
3. The parent reads the saved registers with `PTRACE_GETREGS`.
4. The parent changes RIP with `PTRACE_SETREGS` and continues the child.
5. The selected function prints a marker and exits normally.

No instruction bytes, shellcode, or library are written into the victim. This
isolates register redirection from code staging.

## Build and test

```bash
make
make test
```

The target is deliberately non-PIE so the reported function address is easy to
inspect. It is still sent through a private pipe rather than hardcoded.

## Comparison with the other ptrace labs

- `ptrace_seize` establishes and ends a trace relationship without changing
  memory or registers.
- `ptrace_traceme` lets the child opt into tracing and changes only RIP and the
  stack alignment before executing code already present in the child.
- `ptrace` attaches to an existing PID, writes instruction bytes, and changes
  registers.

The lab exits from the selected function, so it does not demonstrate recovery.
`PTRACE_O_EXITKILL` prevents the controlled child from continuing if its parent
unexpectedly exits.

## Literature connection

The Akamai Linux Process Injection research separates ptrace writes from the
`PTRACE_SETREGS` execution primitive. This lab keeps that separation and uses
`PTRACE_TRACEME` to make the parent-child authorization explicit. `strace` also
documents `PTRACE_TRACEME` as one of the launch paths used by tracing tools.

## Detection notes

- Record `PTRACE_TRACEME`, the stop, `PTRACE_GETREGS`, `PTRACE_SETREGS`, and
  `PTRACE_CONT` as a sequence.
- Parent-child tracing is normal for debuggers and syscall tracers.
- A register change into an unexpected mapping is more specific than
  `PTRACE_TRACEME` alone.
- This example redirects into the victim's own executable mapping and stages no
  new executable memory.

## References

- [`ptrace(2)`](https://man7.org/linux/man-pages/man2/ptrace.2.html)
- [Akamai Linux Process Injection PoCs](https://github.com/akamai/Linux-Process-Injection)
- [Akamai: The Definitive Guide to Linux Process Injection](https://www.akamai.com/blog/security-research/the-definitive-guide-to-linux-process-injection)
- [`strace` internals](https://github.com/strace/strace/blob/master/doc/INTERNALS.md)
