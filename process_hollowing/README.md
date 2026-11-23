# Linux Entry-Point Stomping and Process Hollowing

This x86_64 lab implements the narrow Linux pattern that some research calls
process hollowing:

1. A controlled child calls `PTRACE_TRACEME` and executes a static victim.
2. The kernel stops it with `SIGTRAP` immediately after `exec`, before its first
   user instruction.
3. The parent reads RIP and replaces 16 bytes at that entry point with
   `PTRACE_POKETEXT`.
4. The replacement performs only `exit(42)`.
5. The parent resumes the child and asserts the exit marker.

```bash
make
make test
```

The controller accepts only a program it launches itself. It has no arbitrary
PID mode, stages no shell, and leaves no child running.

## Is this full process hollowing?

Not in the canonical Windows sense. Windows process hollowing usually means
creating a suspended process, unmapping its original image, allocating and
writing a replacement image, changing thread context, and resuming it.

This Linux adaptation overwrites only the first instructions after `exec`. A
more precise name is **entry-point stomping**. The original executable mappings,
auxiliary vector, stack, and process identity remain in place. Replacing all ELF
load segments and rebuilding loader state would be a much larger experiment.

The `linux-prinj` proof of concept uses the same general lifecycle: trace before
`exec`, wait for the exec stop, obtain RIP, overwrite code at RIP, and detach.
This repository narrows the payload to a deterministic exit marker and verifies
child cleanup.

## What it is not

- `memfd_create` plus `fexecve` is fileless execution, but `exec` legitimately
  replaces the process image. It is not hollowing by itself.
- Changing `argv`, `comm`, or a process title is masquerading, not hollowing.
- Loading an extra shared object preserves the original image and is module
  injection or loader hijacking, not hollowing.
- Redirecting RIP in an already-running process is execution hijacking, but it
  becomes hollowing-like only when original image code is replaced at scale.

## Detection notes

- Correlate `PTRACE_TRACEME`, `exec`, the exec-time `SIGTRAP`, code writes, and
  continuation.
- Compare executable mapping bytes with the file backing those mappings.
- Alert when the initial instruction pointer is modified before normal program
  startup.
- Process names and `/proc/<pid>/exe` can still look legitimate after code is
  changed, so identity fields alone are insufficient.
- Debuggers also stop after `exec`; the following code modification and exit
  behavior provide the useful context.

## References

- [linux-prinj process hollowing example](https://github.com/antifob/linux-prinj/tree/main/04-hollowing)
- [linux-prinj `hollow.c`](https://github.com/antifob/linux-prinj/blob/main/04-hollowing/hollow.c)
- [`ptrace(2)`](https://man7.org/linux/man-pages/man2/ptrace.2.html)
- [MITRE ATT&CK Process Hollowing](https://attack.mitre.org/techniques/T1055/012/)
