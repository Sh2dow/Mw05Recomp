# Thread Crash Analysis - 2025-10-15

## Problem Summary
The game creates a new thread with entry point `0x828508A8`, which immediately crashes when trying to call `sub_826BE2B0()`.

## Root Cause
The thread entry point `sub_828508A8` calls two functions:
1. `sub_826BE2C0()` - Returns the value of global variable `dword_828E14E0`
2. `sub_826BE2B0(result)` - Calls a function pointer from a table using the result as an index

### Function Implementations

**sub_826BE2C0** (0x826BE2C0):
```c
int sub_826BE2C0() {
  return dword_828E14E0;  // Global at 0x828E14E0
}
```

**sub_826BE2B0** (0x826BE2B0):
```c
int sub_826BE2B0(int index) {
  int (*func_ptr)(void) = off_828EE5E8[index];  // Function pointer table at 0x828EE5E8
  return func_ptr();
}
```

### The Bug
- `dword_828E14E0` is initialized to `0xFFFFFFFF` (-1) in the XEX data section
- The game expects this global to be initialized to a valid index (0, 1, 2, etc.) before creating the thread
- When `sub_826BE2B0(-1)` is called, it tries to access `off_828EE5E8[-1]`, which is an invalid memory address
- This causes a crash at offset +0x4C21A00 (way beyond the valid code range)

## Investigation Steps

### 1. Check XEX Data
```
Address 0x828E14E0: 0xFFFFFFFF (uninitialized marker)
Address 0x828EE5E8: 0x00080017 (not a valid function pointer)
```

### 2. Check Generated Code
The functions ARE being recompiled correctly:
- `ppc_recomp.86.cpp` lines 20998-21013: Implementations of `sub_826BE2B0` and `sub_826BE2C0`
- `ppc_recomp.88.cpp` lines 3203-3214: Calls from `sub_828508A8`

### 3. Check Runtime Behavior
- No writes to `0x828E14E0` in our trace log
- The global is never being initialized before the thread is created
- The game must initialize it somewhere during startup, but we're not reaching that code

## Next Steps

### Option 1: Find the Initialization Code
Search for functions that write to `dword_828E14E0` and ensure they're called before the thread is created.

### Option 2: Add a Shim
Create a shim for `sub_826BE2C0` that returns a valid index (e.g., 0) instead of -1.

### Option 3: Delay Thread Creation
The thread is being created too early, before the game has finished initialization. We need to find out:
1. What triggers the thread creation?
2. What initialization must happen before the thread is created?
3. How can we delay the thread creation until after initialization?

## Crash Details
```
[*] [crash] unhandled exception code=0xC0000005 addr=0x7ff66a5c1a00 tid=00008D54
[*] [crash]   frame[9] = 0x7ff66a5c1a00 module=Mw05Recomp.exe base=0x7ff6659a0000 +0x4C21A00
```

The crash offset +0x4C21A00 is way beyond the valid code range (should be < 0xCD0000), confirming that the function pointer is garbage.

## Conclusion
The thread is being created before the game has initialized the global variable `dword_828E14E0`. We need to either:
1. Find and call the initialization code before creating the thread
2. Add a shim to provide a default value
3. Delay thread creation until after initialization is complete

