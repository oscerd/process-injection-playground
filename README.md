# Linux Process Injection Playground

A comprehensive collection of process injection techniques for Linux, demonstrating various methods of injecting code into running processes. These examples are intended for educational purposes, security research, and understanding low-level Linux process manipulation.

## Overview

Process injection is a technique used to run code in the context of another process. While often associated with malware, these techniques are also valuable for:

- **Security Research**: Understanding attack vectors and developing defenses
- **Debugging**: Analyzing and modifying running applications
- **Instrumentation**: Performance profiling and monitoring
- **Penetration Testing**: Authorized security assessments
- **CTF Competitions**: Capture The Flag challenges

## Available Techniques

### 1. Ptrace-based Code Injection
**Directory**: `ptrace/`

The classic process injection method using the `ptrace()` system call to directly write shellcode into a process's memory and redirect execution.

**Key Features**:
- Direct memory manipulation via PTRACE_POKETEXT
- Instruction pointer (RIP) hijacking
- Raw shellcode injection

**Use Case**: Understanding low-level process control and direct code injection

[Read more →](ptrace/README.md)

---

### 2. LD_PRELOAD Injection
**Directory**: `ld_preload/`

Function interposition using the `LD_PRELOAD` environment variable to load a malicious library before any other libraries.

**Key Features**:
- Environment variable-based injection
- Function hooking via symbol interposition
- Constructor/destructor functions
- Easy to implement but also easy to detect

**Use Case**: Function hooking, API monitoring, behavior modification

[Read more →](ld_preload/README.md)

---

### 3. /proc/mem Write Injection
**Directory**: `proc_mem/`

Direct memory writing through the `/proc/<pid>/mem` filesystem interface, combined with ptrace for process control.

**Key Features**:
- Direct memory access via filesystem
- More efficient than PTRACE_POKETEXT for large payloads
- Single write operation for entire shellcode
- No word alignment requirements

**Use Case**: Fast bulk memory injection, bypassing traditional ptrace limitations

[Read more →](proc_mem/README.md)

---

### 4. dlopen() Library Injection
**Directory**: `dlopen_inject/`

Sophisticated technique that forces a running process to load a shared library by hijacking execution to call `dlopen()`.

**Key Features**:
- Works on already-running processes (unlike LD_PRELOAD)
- Persistent (library remains loaded)
- Enables complex payloads with full library capabilities
- Can hook functions like LD_PRELOAD but post-startup

**Use Case**: Advanced persistent injection, runtime library manipulation

[Read more →](dlopen_inject/README.md)

---

## Quick Start

### Prerequisites

- Linux system (tested on x86_64)
- GCC compiler
- Root access or CAP_SYS_PTRACE capability
- Make build tool

### Building All Examples

```bash
# Build ptrace injection
cd ptrace && make all

# Build LD_PRELOAD injection
cd ../ld_preload && make all

# Build /proc/mem injection
cd ../proc_mem && make all

# Build dlopen injection
cd ../dlopen_inject && make all
```

### Basic Usage Pattern

Each technique follows a similar pattern:

1. **Start the victim process**:
   ```bash
   cd <technique>/victim-process
   ./sample
   ```
   Note the PID displayed

2. **Perform injection**:
   ```bash
   cd <technique>
   sudo ./<injector> <PID> [additional args]
   ```

3. **Observe results**: Check victim process output for injected code execution

See individual README files for technique-specific instructions.

## Comparison Matrix

| Technique | Complexity | Stealth | Persistence | Speed | Works on Running Process |
|-----------|-----------|---------|-------------|-------|-------------------------|
| **ptrace** | Medium | Low | No | Medium | Yes |
| **LD_PRELOAD** | Low | Very Low | No | Fast | No |
| **/proc/mem** | Medium | Low | No | Fast | Yes |
| **dlopen** | High | Medium | Yes | Medium | Yes |

### When to Use Which?

- **ptrace**: Learning fundamentals, simple shellcode injection
- **LD_PRELOAD**: Quick function hooking, debugging, when you control process startup
- **/proc/mem**: Fast injection of large payloads, when PTRACE_POKETEXT is too slow
- **dlopen**: Persistent injection, complex payloads, when you need full library capabilities

## Security Considerations

### Defensive Measures

1. **Yama ptrace_scope**: Restrict ptrace to privileged users
   ```bash
   echo 1 | sudo tee /proc/sys/kernel/yama/ptrace_scope
   ```

2. **SELinux/AppArmor**: Mandatory access controls

3. **Monitoring**: Use auditd to log ptrace and process injection attempts
   ```bash
   auditctl -a exit,always -F arch=b64 -S ptrace
   ```

4. **Runtime Integrity Checking**: Periodically verify process memory

5. **Code Signing**: Verify library signatures

### Detection Methods

- Monitor `/proc/<pid>/maps` for unexpected memory regions or libraries
- Watch for ptrace attach attempts via system logs
- Check environment variables (LD_PRELOAD)
- Use tools like `lsof`, `pmap`, and process monitoring utilities
- Enable kernel security modules

## Legal and Ethical Notice

**IMPORTANT**: These techniques should only be used in authorized contexts:

**This repository is for educational and research purposes only.** The authors are not responsible for misuse of these techniques. Always obtain proper authorization before testing on any system.

## Troubleshooting

### Common Issues

**Permission denied errors**:
- Run with `sudo`
- Check `/proc/sys/kernel/yama/ptrace_scope`
- Verify SELinux/AppArmor policies

**Injection fails silently**:
- Verify target process is not statically linked
- Check that target process has required libraries loaded
- Ensure shellcode is correct for your architecture

**Segmentation faults**:
- Verify you're on x86_64 architecture
- Check that target process is not protected
- Ensure proper memory alignment

See individual technique READMEs for specific troubleshooting guidance.

## Contributing

Contributions are welcome! Potential additions:

- Additional injection techniques (GOT/PLT hooking, VDSO manipulation, etc.)
- Windows equivalents for comparison
- Detection/prevention tools
- ARM architecture support
- Additional shellcode examples
- Defensive programming examples

## References

### Documentation
- `man 2 ptrace` - Process tracing system call
- `man 5 proc` - /proc filesystem documentation
- `man 3 dlopen` - Dynamic library loading
- Linux kernel source: process memory management

### Related Research
- "Linux Process Injection" techniques and evolution
- "Ptrace Injection" methodologies
- "Shared Library Injection" best practices
- MITRE ATT&CK: T1055 (Process Injection)

## License

See [LICENSE.txt](LICENSE.txt) for details.

## Disclaimer

This software is provided "as is" for educational purposes. Use responsibly and ethically. Always obtain proper authorization before testing security techniques on any system you do not own.
