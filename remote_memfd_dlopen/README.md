# Remote `memfd` and `dlopen` Comparison

This controlled x86_64 lab compares two remote `dlopen` calls against the same
purpose-built child:

- an ordinary absolute path to an on-disk shared object;
- `/proc/self/fd/<fd>` for a shared object held in an inherited `memfd`.

The parent creates and populates the `memfd` before spawning the child. The
child inherits that descriptor across `exec`. The remote operation is the
ptrace-driven call to `dlopen`; this lab does not claim to create or populate a
new file descriptor inside an arbitrary running process.

## What the lab proves

For both modes, the injector:

1. spawns the included victim and receives addresses for dedicated patch,
   pathname, and stack regions;
2. attaches with ptrace and saves registers plus every temporary region;
3. resolves the target's `dlopen` address from the matching loader mapping;
4. writes a short `dlopen(path, RTLD_NOW | RTLD_LOCAL)` call stub;
5. uses a dedicated 64 KiB stack instead of the victim's active stack;
6. regains control through `INT3` and verifies the resulting library mapping;
7. restores the patch bytes, pathname storage, dedicated stack, and registers;
8. detaches and confirms that the victim still responds to a signal and exits
   normally.

The benign shared-object constructor writes one byte to a test pipe. It does
not start a shell, open a network connection, or target an external process.

## Build and run

```bash
make
make test
```

Run the modes individually:

```bash
./inject --mode disk --library ./demo_lib.so \
  --spawn ./victim-process/sample
./inject --mode memfd --library ./demo_lib.so \
  --spawn ./victim-process/sample
```

A ptrace or `memfd_create` policy denial returns status 77 so the repository
test can report a skip without changing host security settings.

## Comparison

| Property | Disk mode | Memfd mode |
| --- | --- | --- |
| Path passed to target `dlopen` | Absolute filesystem path | `/proc/self/fd/<fd>` |
| Backing object | Named file | Anonymous file descriptor |
| Expected mapping text | Shared-object pathname | `memfd:remote-dlopen-demo (deleted)` |
| Remote call sequence | Same ptrace stub | Same ptrace stub |
| State restored | Patch, pathname, stack, registers | Patch, pathname, stack, registers |
| State intentionally retained | Loaded object | Loaded object and inherited descriptor |

The source shared object begins on disk in both automated cases. Memfd mode
copies those bytes into the anonymous file before starting the child; it is not
a reflective ELF loader.

## Detection notes

Correlate the ptrace attach, memory and register writes, `INT3` stop, and detach
with the new shared-object mapping. Memfd mode additionally exposes a memfd
creation and a mapping whose pathname contains `memfd:` and `(deleted)`.
Debugger, hot-patching, observability, and test tooling can produce similar
ptrace and loader activity, so ancestry and target identity remain important.

## Assumptions and limitations

- x86_64 System V calling convention;
- injector and victim use a compatible glibc layout;
- a single-threaded, repository-owned victim;
- an inherited descriptor rather than a remotely created descriptor;
- the loaded object remains mapped after temporary injection state is restored.

## References

- [`memfd_create(2)`](https://man7.org/linux/man-pages/man2/memfd_create.2.html)
- [`dlopen(3)`](https://man7.org/linux/man-pages/man3/dlopen.3.html)
- [`ptrace(2)`](https://man7.org/linux/man-pages/man2/ptrace.2.html)
- [dlinject restoration-oriented loader](https://github.com/DavidBuchanan314/dlinject)
- [Detecting Shared Object Injection](https://virusbulletin.com/uploads/pdf/conference/vb2024/papers/Detecting-Shared-Object-injection.pdf)
