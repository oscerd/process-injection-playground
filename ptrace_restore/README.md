# Ptrace Save, Trap, Restore, and Resume

This controlled x86_64 lab demonstrates a complete ptrace modification
lifecycle without leaving injected state in the victim.

## Lifecycle

1. The injector spawns the included victim and attaches with `PTRACE_ATTACH`.
2. It saves the general-purpose register set, 32 bytes from a dedicated
   executable patch slot, and the original data marker.
3. It installs a benign stub that writes a fixed marker and executes `INT3`.
4. It redirects RIP to the patch slot and continues the victim.
5. The `INT3` stop returns control to the injector, which verifies that the
   marker was written.
6. The injector restores the original code, marker, and registers.
7. It reads everything back and compares it with the saved state before
   detaching.
8. After detach, the victim acknowledges `SIGUSR1`, confirms that its marker is
   zero, and exits normally.

This separates successful temporary execution from reliable recovery. The
payload is only a deterministic data marker; no shellcode or external PID mode
is provided.

## Build and run

```bash
make
make test
```

Run the test directly:

```bash
./inject --spawn ./victim-process/sample
```

If the environment denies the parent-child ptrace attach, the injector returns
status 77 and the Makefile reports a skip. It never changes Yama or another
host security control.

## Expected evidence

The ptrace request sequence includes:

```text
PTRACE_ATTACH
PTRACE_GETREGS
PTRACE_PEEKDATA / PTRACE_POKEDATA
PTRACE_SETREGS
PTRACE_CONT
SIGTRAP stop
PTRACE_SETREGS
PTRACE_DETACH
```

The same high-level sequence can be produced by debuggers and live
instrumentation. Detection should distinguish temporary modifications that are
restored from modifications that remain, while still treating the complete
write-and-execute chain as security-relevant.

## Assumptions and limitations

- x86_64 registers and machine instructions;
- a single-threaded, repository-owned victim;
- a dedicated executable patch slot rather than arbitrary instruction bytes;
- no signal race or thread-group coordination beyond the controlled protocol.

Multi-threaded recovery and asynchronous-signal handling remain separate
future experiments.

## References

- [`ptrace(2)`](https://man7.org/linux/man-pages/man2/ptrace.2.html)
- [Akamai Linux Process Injection PoCs](https://github.com/akamai/Linux-Process-Injection)
- [dlinject restoration-oriented loader](https://github.com/DavidBuchanan314/dlinject)
