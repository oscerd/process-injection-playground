# Controlled VDSO Function Replacement

This x86_64 lab demonstrates temporary modification of the Linux virtual
dynamic shared object, or VDSO, in a repository-owned child process.

The victim resolves `__vdso_gettimeofday` from `linux-vdso.so.1` and publishes
its address. The injector verifies that the address belongs to the child's
`[vdso]` mapping, replaces the first bytes with a fixed `return 42` stub, and
asks the victim to call the function directly. After observing the marker, it
restores and verifies the original bytes before detaching. The victim calls the
restored function again and must receive the normal return value.

## Scope

This is a narrow VDSO execution-surface experiment related to
[MITRE ATT&CK T1055.014](https://attack.mitre.org/techniques/T1055/014/). It is
not the complete chain described by ATT&CK, which can combine VDSO code, GOT
redirection, syscalls, and loading a separate shared object.

The lab does not:

- accept an arbitrary PID;
- install a library or persistent payload;
- modify a GOT entry;
- leave the VDSO bytes changed after the test.

## Build and run

```bash
make
make test
```

Run the controlled case directly:

```bash
./injector --spawn ./victim-process/sample
```

Status 77 means that ptrace access is blocked or that the selected VDSO symbol
is unavailable. The test never changes host security settings.

## Lifecycle

1. Resolve `__vdso_gettimeofday` inside the victim.
2. Verify that the address falls inside `/proc/<pid>/maps` entry `[vdso]`.
3. Attach and save eight original instruction bytes.
4. Install `mov eax, 42; ret` and deliver `SIGUSR1` to the stopped child.
5. Observe the return marker and regain control through `SIGTRAP`.
6. Restore and read back the original VDSO bytes.
7. Detach, invoke the restored function, and confirm normal process exit.

## Detection notes

Useful evidence includes ptrace writes whose destination belongs to `[vdso]`,
temporary divergence between VDSO memory and its expected kernel-provided
image, signal stops, and later execution at the modified address. A debugger or
specialized instrumentation tool can also modify executable memory, so target
identity and write destination are important context.

## Assumptions

- x86_64 instruction encoding;
- `linux-vdso.so.1` exports `__vdso_gettimeofday`;
- a single-threaded controlled child;
- ptrace permits the parent-child relationship.

## References

- [MITRE ATT&CK T1055.014: VDSO Hijacking](https://attack.mitre.org/techniques/T1055/014/)
- [`ptrace(2)`](https://man7.org/linux/man-pages/man2/ptrace.2.html)
- [`vdso(7)`](https://man7.org/linux/man-pages/man7/vdso.7.html)
