# /proc/mem Process Injection

## Overview

This technique demonstrates process injection by directly writing to `/proc/<pid>/mem`, which is a file that represents the entire address space of a process. Unlike ptrace-based memory writes (PTRACE_POKETEXT), this method writes directly to the memory file.

## How It Works

1. **Attach with ptrace**: Use `PTRACE_ATTACH` to pause the target process
2. **Find executable region**: Parse `/proc/<pid>/maps` to find a suitable memory region with execute permissions
3. **Open /proc/mem**: Open `/proc/<pid>/mem` for reading and writing
4. **Write shellcode**: Use `lseek()` + `write()` to inject shellcode at the target address
5. **Redirect execution**: Modify the instruction pointer (RIP) to point to shellcode
6. **Detach**: Let the process continue with injected code

## Requirements

- Root privileges or `CAP_SYS_PTRACE` capability
- Kernel must support `/proc/<pid>/mem` access (enabled by default on most modern systems)
- Target process must not be running as root (unless injector is also root)

## Building

```bash
make all
```

This creates:
- `inject` - The injection tool
- `victim-process/sample` - The victim process

## Usage

### Step 1: Start the victim process

```bash
./victim-process/sample
```

The victim will print its PID. Example output:
```
Victim Process Started
PID: 12345
Waiting for injection...
```

### Step 2: Inject shellcode

In another terminal:

```bash
sudo ./inject <victim_pid>
```

Example:
```bash
sudo ./inject 12345
```

### Expected Output

**Injector output:**
```
=== /proc/mem Process Injection ===
[*] Target PID: 12345
[*] Attaching to process 12345...
[+] Attached successfully
[+] Found executable region: 0x7ffff7dd5000-0x7ffff7dfc000 (r-x)
[*] Injection address: 0x7ffff7dd5000
[*] Writing shellcode via /proc/12345/mem...
[+] Wrote 30 bytes of shellcode
[+] RIP redirected to 0x7ffff7dd5000
[*] Detaching and executing shellcode...
[+] Injection complete!

[SUCCESS] Shellcode injected and executed!
[INFO] Check the victim process - it should now have a shell
```

**Victim process:**
The victim process terminal will now have a shell spawned within it.

## Technical Details

### Memory Layout

The injector parses `/proc/<pid>/maps` to find suitable injection points:

```
7ffff7dd5000-7ffff7dfc000 r-xp 00000000 08:01 12345  /lib/x86_64-linux-gnu/ld-2.31.so
```

Fields:
- `7ffff7dd5000-7ffff7dfc000`: Address range
- `r-xp`: Permissions (read, execute, private)
- We look for regions with `r-x` permissions

### Shellcode

The included shellcode executes:
```c
execve("/bin/sh", NULL, NULL);
```

This spawns a shell in the context of the victim process.

### /proc/mem Access

- `/proc/<pid>/mem` represents the entire virtual address space
- Must use `lseek()` to position at the correct offset before writing
- Requires ptrace attachment to write to another process's memory
- More direct than PTRACE_POKETEXT which copies word-by-word

## Detection and Prevention

**Detection:**
- Monitor ptrace attach attempts
- Watch for suspicious `/proc/<pid>/mem` access
- Use tools like `auditd` to log process tracing
- Check for unexpected changes in process memory maps

**Prevention:**
- Enable Yama ptrace_scope: `echo 1 > /proc/sys/kernel/yama/ptrace_scope`
- Use SELinux or AppArmor to restrict ptrace
- Enable kernel security modules
- Use address space layout randomization (ASLR)
- Implement runtime integrity checking

## Troubleshooting

### Permission denied on /proc/mem

- Ensure you're running as root or have `CAP_SYS_PTRACE`
- Check Yama ptrace_scope: `cat /proc/sys/kernel/yama/ptrace_scope`
- If scope is 1, temporarily set to 0: `echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope`

### Failed to find executable region

- The victim process may not have suitable memory regions
- Try running the victim with different libraries loaded

### Write to /proc/mem fails

- Some kernels restrict /proc/mem writes
- Ensure ptrace is attached before opening /proc/mem
- Check kernel version and configuration

## Cleanup

```bash
make clean
```

## References

- `man 5 proc` - Documentation for /proc filesystem
- `man 2 ptrace` - Process tracing system call
- Linux kernel source: `fs/proc/base.c` - Implementation of /proc/mem
