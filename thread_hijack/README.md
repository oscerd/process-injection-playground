# Multi-thread Ptrace Redirection and Recovery

Ptrace operates on individual Linux threads, not an entire process as a single
tracee. This x86_64 lab makes that distinction observable with a controlled
process containing three worker threads.

The injector enumerates `/proc/<pid>/task`, seizes every TID, interrupts the
whole thread group, and redirects exactly one published worker through a benign
marker stub. The other threads remain stopped. After the selected worker traps,
the injector restores its code, data, and general-purpose registers, detaches
every TID, and wakes each worker. The process must join all workers and exit
normally.

## Build and run

```bash
make
make test
```

Run the controlled case directly:

```bash
./injector --spawn ./victim-process/sample
```

The test returns status 77 when thread-group tracing is denied. It does not
lower Yama settings or attach to an external PID.

## Lifecycle

1. The victim creates three workers and publishes their TIDs, a selected TID,
   a dedicated executable patch slot, and a data marker.
2. The injector independently enumerates the task directory and checks that it
   sees the leader plus all three workers.
3. It applies `PTRACE_SEIZE` and `PTRACE_INTERRUPT` to every TID.
4. It saves state only for the selected worker, installs a benign marker stub,
   cancels the interrupted syscall restart, and redirects that worker's RIP.
5. The selected worker writes the marker and stops through `INT3`; the other
   TIDs remain stopped.
6. Code, data, and every general-purpose register are restored and verified.
7. Every TID is detached. Thread-directed `SIGUSR1` wakes each worker and the
   selected worker acknowledges resumed execution.

Cancelling the interrupted syscall restart by setting `orig_rax` to `-1` is
important here. A worker interrupted while sleeping in `pause` could otherwise
restart that syscall instead of entering the temporary patch slot.

## Detection notes

High-signal behavior includes one tracer enumerating the task directory,
seizing several TIDs from the same thread group, interrupting all of them, and
then writing code or registers for only one TID. Debuggers can legitimately
perform a similar stop-the-world sequence, so correlate executable identity,
ancestry, destination addresses, and whether state is restored.

## Deliberate limitations

- the victim creates no new threads after publishing readiness;
- the example does not exercise `PTRACE_O_TRACECLONE`;
- signal delivery is deterministic and controlled;
- the marker stub is x86_64-specific;
- no arbitrary PID or shell payload is available.

Future work can add clone races, asynchronous signals, and thread exit while a
tracer is coordinating the group.

## References

- [`ptrace(2)` per-thread semantics](https://man7.org/linux/man-pages/man2/ptrace.2.html)
- [Jugaad: Run-time Thread Injection](https://magazine.hitb.org/wp-content/uploads/2021/05/HITB-Ezine-Issue-006.pdf)
