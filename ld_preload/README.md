# LD_PRELOAD Injection

## Overview

LD_PRELOAD is an environment variable that allows you to specify one or more shared libraries to be loaded before any other libraries when a program is executed. This technique is commonly used for:

- Function interposition (hooking)
- Debugging and profiling
- Security research and testing
- Malware analysis

## How It Works

1. The dynamic linker loads the LD_PRELOAD library first
2. Constructor functions (`__attribute__((constructor))`) run before main()
3. Functions in the preloaded library override standard library functions
4. The original functions can still be called using `dlsym(RTLD_NEXT, "function_name")`

## Building

```bash
make all
```

This creates:
- `injected_lib.so` - The malicious shared library
- `victim-process/sample` - The victim process

## Usage

### Method 1: Set LD_PRELOAD environment variable

```bash
# Run victim process normally (no injection)
./victim-process/sample

# In another terminal, run with LD_PRELOAD
LD_PRELOAD=./injected_lib.so ./victim-process/sample
```

### Method 2: Export LD_PRELOAD globally (affects all programs)

```bash
export LD_PRELOAD=$(pwd)/injected_lib.so
./victim-process/sample
unset LD_PRELOAD  # Clean up
```

### Method 3: Inject into running process

```bash
# Start the victim
./victim-process/sample &
VICTIM_PID=$!

# Inject the library (requires gdb)
gdb -p $VICTIM_PID -batch \
    -ex "call (void*)dlopen(\"$(pwd)/injected_lib.so\", 2)" \
    -ex "detach" \
    -ex "quit"
```

## What Gets Hijacked

This example demonstrates interception of:

1. **printf()** - Adds "[HIJACKED]" prefix to all printf calls
2. **puts()** - Displays injection message
3. **write()** - Logs all write operations to stdout/stderr
4. **Constructor/Destructor** - Runs code before/after main()

## Expected Output

When running with LD_PRELOAD, you should see:

```
[INJECTED] Library loaded! PID: 12345
[INJECTED] This code runs before main()
[HIJACKED] Victim Process Started (PID: 12345)
[HIJACKED] Normal execution - Counter: 0
[HIJACKED] Library injected via LD_PRELOAD!
This is a normal puts() call
[INJECTED] Intercepted write() call
...
```

## Detection and Prevention

**Detection:**
- Check `/proc/<pid>/maps` for unexpected libraries
- Monitor LD_PRELOAD environment variable
- Use `ldd` to see loaded libraries

**Prevention:**
- Use setuid/setgid binaries (LD_PRELOAD is ignored)
- Static linking
- Code signing and verification
- Restrict write access to library directories

## Cleanup

```bash
make clean
```

## Notes

- This technique requires the ability to set environment variables
- Does not work on setuid/setgid binaries for security reasons
- Very easy to detect but useful for educational purposes
- Can be combined with other techniques for persistence
