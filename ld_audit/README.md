# `LD_AUDIT` Dynamic-Linker Callbacks

This lab uses glibc's runtime-linker auditing API. An audit library receives
notifications when the loader opens ELF objects and binds selected symbols.
The example records `puts` binding and returns the original symbol address, so
the victim's behavior remains unchanged.

## Build and test

```bash
make
make test
```

The test launches a controlled victim with an absolute `LD_AUDIT` path and
asserts the loader handshake, object-open callback, symbol-binding callback,
and normal victim output.

## How it differs from `LD_PRELOAD`

- `LD_PRELOAD` places a library into the normal symbol-resolution scope and can
  override symbols through interposition.
- `LD_AUDIT` loads an audit module into a separate linker namespace and invokes
  its defined auditing callbacks.
- Both are controlled-launch environment mechanisms, not modification of an
  already-running process.

The auditing API permits a callback to return a different binding address, but
this lab intentionally returns `symbol->st_value` and only observes the event.

## Detection and limitations

- Inspect process-launch environments for unexpected `LD_AUDIT` values.
- Correlate the audit library path with process identity and provenance.
- Secure-execution mode strips or restricts dynamic-linker environment
  variables, so this mechanism does not apply uniformly to privileged targets.
- This example targets the GNU dynamic linker and is not a portable interface
  across all C libraries.

## ATT&CK mapping

This is a benign use of a dynamic-linker environment variable. Abuse belongs
under the broader dynamic-linker hijacking family, T1574.006, rather than live
process injection.

## References

- [`rtld-audit(7)`](https://man7.org/linux/man-pages/man7/rtld-audit.7.html)
- [`ld.so(8)`](https://man7.org/linux/man-pages/man8/ld.so.8.html)
- [MITRE ATT&CK T1574.006](https://attack.mitre.org/techniques/T1574/006/)
