# Glossary

## Access primitive

The kernel interface and policy decision that let one process inspect or modify
another. Credentials, dumpability, capabilities, Yama, and other Linux Security
Modules participate in the decision.

## Controlled launch

A process start where the experiment controls arguments, environment variables,
file descriptors, or loader configuration. `LD_PRELOAD` and `LD_AUDIT` are
controlled-launch mechanisms.

## Execution trigger

The event that transfers control to a selected address. Examples include a
changed instruction pointer, a replaced return address, an indirect call through
a modified function pointer, or a temporary stub that calls `dlopen`.

## Function interposition

Providing a symbol definition that is selected before another implementation by
the dynamic linker's lookup rules. Interposition is not synonymous with remote
process injection.

## Injection

Executing selected code in the address space of a separate live process. A
remote write alone is incomplete unless the desired behavior is data-only or a
separate execution trigger consumes the changed data.

## Memory-backed object

An object stored in an anonymous or temporary memory file, such as a memfd,
rather than a persistent pathname. Memory-backed does not mean invisible: file
descriptors, mappings, and memory contents remain observable.

## Ptrace access-mode check

A kernel authorization check reused by ptrace and other cross-process
interfaces, including `/proc/<pid>/mem` and `process_vm_writev`. A technique can
avoid calling the `ptrace` syscall while still being governed by ptrace policy.

## Recovery

Restoring overwritten bytes, registers, signal state, and thread execution after
a demonstration. Reliable recovery is separate from successful execution.

## Reflective loading

Loading code into the current process from memory or an anonymous object instead
of using a normal persistent module path. It differs from remote-process
injection because no separate process must be modified.

## Remote write

Copying bytes into another process's address space. This may target ordinary
data, a control-flow value, or executable instructions.

## Staging

Placing data or code where a later execution mechanism can consume it. Staging
and execution can use different primitives.

## Tracee and tracer

Ptrace terminology for the controlled thread and the process controlling it.
Linux ptrace attachment is per thread, even when tools present a process-level
interface.
