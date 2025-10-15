# Thread Crash Debugging Status

## Date: 2025-10-16

## Current Status
The game crashes when creating a new thread with entry point `0x828508A8`. The crash happens BEFORE any of the debug logging in `GuestThread::Start` appears, suggesting the crash occurs during thread context initialization or even earlier.

## Crash Details
- **Crash offset**: `+0x4C21B40` (changed from `+0x4C21A70` after rebuild)
- **Crash address**: `0x7ff7aa911b40`
- **Thread ID**: `00008D34` (newly created thread)
- **Entry point**: `0x828508A8` (sub_828508A8)
- **Context**: `0x7FEA15A0`
- **Exception code**: `0xC0000005` (access violation)

## Trace Evidence
```
[*] [TRACE] import=HOST.ExCreateThread entry=828508A8 ctx=7FEA15A0 flags=00000001
[*] [TRACE] import=HOST.ExCreateThread DONE entry=828508A8 hostTid=00008D34
[*] [TRACE] import=HOST.NtResumeThread tid=00008D34
[*] [crash] unhandled exception code=0xC0000005 addr=0x7ff7aa911b40 tid=00008D34
```

## Debug Logging Added
Added debug logging to `Mw05Recomp/cpu/guest_thread.cpp` at lines 212-228:
```cpp
fprintf(stderr, "[DEBUG] entryFunc=%p (found for guest=0x%08X)\n", (void*)entryFunc, params.function);
fprintf(stderr, "[DEBUG] About to call entryFunc...\n");
fprintf(stderr, "[DEBUG] Calling entryFunc NOW...\n");
entryFunc(ctx.ppcContext, g_memory.base);
fprintf(stderr, "[DEBUG] entryFunc returned successfully\n");
```

**Result**: NONE of these messages appeared in the output!

## Analysis

### What This Means
The crash is happening BEFORE the `GuestThread::Start` function reaches line 212. This means the crash occurs in one of these locations:

1. **Thread startup code** (before `GuestThread::Start` is called)
2. **`GuestThreadContext` constructor** (line 22-56 in guest_thread.cpp)
3. **`SetPPCContext` call** (line 51 in guest_thread.cpp)
4. **`FindFunction` call** (line 210 in guest_thread.cpp)

### Crash Location Analysis
The crash offset `+0x4C21B40` is in the FUNCTION TABLE region (after PPC image data at `base + PPC_IMAGE_SIZE`).

Calculating the PPC address:
- `PPC_IMAGE_SIZE = 0x00CD0000`
- `crash_offset = 0x4C21B40`
- `table_offset = 0x4C21B40 - 0x00CD0000 = 0x03F51B40`
- `ppc_offset = 0x03F51B40 / 8 = 0x007EA368`
- `ppc_address = 0x820E0000 + 0x007EA368 = 0x828CA368`

So the crash is happening when trying to call function at address `0x828CA368`.

### Hypothesis
The crash is happening when the thread tries to call a function that's NOT in the TOML, so the function table entry is NULL or invalid. The thread entry point `0x828508A8` is in the TOML, but it might be calling another function that's missing.

## Next Steps

### 1. Add More Debug Logging
Add logging to earlier points in the thread startup:
- `GuestThreadContext` constructor entry/exit
- `SetPPCContext` call
- `FindFunction` call
- Thread function wrapper entry

### 2. Check Function Table Entry
Verify that the function table entry for `0x828508A8` is valid:
- Check if `g_memory.FindFunction(0x828508A8)` returns a valid pointer
- Check if the function pointer is in the correct range
- Check if the function table is properly initialized

### 3. Identify Missing Function
Calculate which function is at address `0x828CA368`:
- Check if this address is in the TOML
- If not, add it to the TOML and regenerate
- Check what function calls this address

### 4. Compare with Xenia
Check if Xenia creates the same thread and what happens:
- Does Xenia call the same entry point?
- Does Xenia crash at the same location?
- What functions does Xenia call during thread startup?

## Files to Check
- `Mw05Recomp/cpu/guest_thread.cpp` - Thread startup code
- `Mw05Recomp/kernel/memory.cpp` - `FindFunction` implementation
- `Mw05RecompLib/config/MW05.toml` - Function list
- `Mw05RecompLib/ppc/ppc_recomp.99.cpp` - Generated code for `sub_828508A8`

## Recommended Action
Add debug logging to `GuestThreadContext` constructor to see if it's being called, and check if the function table entry for `0x828508A8` is valid.

## Update: 2025-10-16 (Debug Logging Added)

### Debug Logging Results
Added extensive debug logging to `GuestThreadFunc` wrapper at lines 87-112 in `guest_thread.cpp`:
- `[GUEST_THREAD_WRAPPER] Entry point reached` - Should appear when wrapper starts
- `[GUEST_THREAD_WRAPPER] hThread=%p, checking suspended flag...` - Should appear after arg cast
- `[GUEST_THREAD_WRAPPER] suspended=%d, tid=%08X, entry=%08X` - Should appear after loading suspended flag

**Result**: NONE of these messages appeared in the test output!

### Analysis
The crash happens BEFORE the `GuestThreadFunc` wrapper is even called. The sequence is:
1. Main thread (tid=000050F4) calls `ExCreateThread` → creates thread tid=00003D40
2. Main thread calls `NtResumeThread` → resumes thread tid=00003D40
3. Thread tid=00003D40 crashes immediately at `+0x4C21BE0` (function table region)
4. NO wrapper debug messages appear

This means the crash is happening during C++ thread startup, BEFORE the wrapper function is invoked. The crash is likely in:
- C++ `std::thread` constructor
- C++ runtime thread initialization
- Windows thread startup code
- Function table lookup during thread initialization

### Crash Location Analysis
- Crash offset: `+0x4C21BE0` (changed from `+0x4C21B40` after rebuild)
- Crash address: `0x7ff6fbde1be0`
- Thread: tid=00003D40 (newly created thread)
- Exception: 0xC0000005 (access violation)

The crash offset is in the function table region (after PPC image data at `base + PPC_IMAGE_SIZE`).

### Hypothesis
The crash is happening when the C++ runtime tries to call the thread entry point function. The function pointer might be:
1. Stored incorrectly in the `GuestThreadHandle` structure
2. Corrupted during thread creation
3. Pointing to an invalid location in the function table
4. Not properly initialized before the thread starts

### Next Steps
1. Add debug logging to `GuestThreadHandle` constructor to verify the function pointer is stored correctly
2. Add debug logging to the C++ thread creation code to see if the thread is being created properly
3. Check if the function pointer is valid before creating the thread
4. Investigate if there's a race condition between thread creation and function pointer initialization

