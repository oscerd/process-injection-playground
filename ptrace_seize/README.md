# `PTRACE_SEIZE` and Explicit Interruption

This lab demonstrates a safe ptrace control sequence:

1. Start a controlled child process.
2. Establish a trace relationship with `PTRACE_SEIZE`.
3. Stop it explicitly with `PTRACE_INTERRUPT`.
4. Observe the ptrace stop.
5. Detach without modifying memory or registers.

Unlike `PTRACE_ATTACH`, `PTRACE_SEIZE` does not stop the tracee as part of the
attach operation. It is useful for understanding how tracing, stopping, and
state modification are separate stages.

## Build and test

```bash
make
make test
```

Expected output includes:

```text
[*] Seizing child PID ... without an attach-time SIGSTOP
[+] Trace relationship established; requesting an explicit stop
[+] Tracee stopped with signal ...
[+] Detached cleanly; no memory or registers were modified
```

The observer uses `PTRACE_O_EXITKILL` so an unexpected tracer exit does not
leave the controlled tracee running.

## Why this is not injection

This example establishes process control but never writes memory, changes
registers, or redirects execution. It is a prerequisite primitive and a useful
legitimate comparison for ptrace-based injection telemetry. A complete
T1055.008 chain requires additional modification behavior.

## Detection notes

- Record the ptrace request, not only the presence of the `ptrace` syscall.
- `PTRACE_SEIZE` followed by `PTRACE_INTERRUPT` has different signal behavior
  from `PTRACE_ATTACH`.
- Debuggers, profilers, crash handlers, and observability tools are expected
  legitimate users.
- Correlate tracing with later `POKETEXT`, `POKEDATA`, `POKEUSER`, or register
  modification requests before classifying the sequence as injection.

## References

- [`ptrace(2)`](https://man7.org/linux/man-pages/man2/ptrace.2.html)
- [MITRE ATT&CK T1055.008](https://attack.mitre.org/techniques/T1055/008/)
