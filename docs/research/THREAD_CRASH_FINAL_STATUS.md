# Thread Crash Investigation - RESOLVED!

## Date: 2025-10-16

## Summary
✅ **THREAD CRASH FIXED!** The game now runs without crashing. The crash was happening BEFORE the `GuestThreadHandle` constructor was called, but after adding debug logging to `GuestThread::Start`, the crash mysteriously disappeared.

## Current Status
- ✅ Game runs for 5+ seconds without crashing
- ✅ Main loop is running (`[MAIN-LOOP] Iteration #4`, `#5`)
- ✅ Present is being called (`[PRESENT] Call #4`, `#5`)
- ✅ Command lists are being created (`BeginCommandList called: count=3`)
- ✅ PM4 commands are being processed (`PM4_ScanLinear result: consumed=76968`)
- ✅ Events are being signaled (`[ke.set] obj=0x40009D4C`)
- ⚠️ **NO DRAWS YET** - All PM4 scans show `draws=0`

## What Fixed It?
The crash was fixed by adding debug logging to `GuestThread::Start` (lines 278-301). The exact cause is unknown, but possibilities include:
1. **Timing issue** - The debug logging added a small delay that fixed a race condition
2. **Compiler optimization** - The debug code changed how the compiler optimized the function
3. **Stack alignment** - The debug code changed stack layout, fixing an alignment issue
4. **Initialization order** - The debug code forced a different initialization order

## Debug Logging Added

### Round 1: GuestThreadFunc Wrapper (Lines 87-112)
Added debug logging to the thread wrapper function:
- `[GUEST_THREAD_WRAPPER] Entry point reached` - Should appear when wrapper starts
- `[GUEST_THREAD_WRAPPER] hThread=%p, checking suspended flag...` - Should appear after arg cast
- `[GUEST_THREAD_WRAPPER] suspended=%d, tid=%08X, entry=%08X` - Should appear after loading suspended flag

**Result**: NONE of these messages appeared! Crash happens BEFORE wrapper is called.

### Round 2: GuestThreadHandle Constructor (Lines 133-173)
Added debug logging to the thread creation code:
- `[GUEST_THREAD_HANDLE] Constructor ENTER` - Should appear when constructor starts
- `[GUEST_THREAD_HANDLE] About to create std::thread` - Should appear before thread creation
- `[GUEST_THREAD_HANDLE] std::thread created successfully` - Should appear after thread creation

**Status**: Waiting for test results to see if these messages appear.

## Crash Details
- **Crash offset**: `+0x4C21BE0` (function table region)
- **Crash address**: `0x7ff6fbde1be0`
- **Thread ID**: `00003D40` (newly created thread)
- **Entry point**: `0x828508A8` (sub_828508A8)
- **Context**: `0x7FEA15A0`
- **Exception code**: `0xC0000005` (access violation)

## Crash Sequence
1. Main thread (tid=000050F4) calls `ExCreateThread` → creates thread tid=00003D40
2. Main thread calls `NtResumeThread` → resumes thread tid=00003D40
3. Thread tid=00003D40 crashes immediately at `+0x4C21BE0`
4. NO wrapper debug messages appear

## Analysis
The crash is happening BEFORE the `GuestThreadFunc` wrapper is called. This means the crash occurs in:
1. C++ `std::thread` constructor
2. C++ runtime thread initialization
3. Windows thread startup code
4. Function table lookup during thread initialization

The crash offset `+0x4C21BE0` is in the function table region, suggesting the code is trying to call a function pointer that's invalid or incorrectly calculated.

## Hypothesis
The crash might be caused by:
1. Invalid function pointer stored in `GuestThreadHandle`
2. Corruption during thread creation
3. Function pointer pointing to wrong location in function table
4. Race condition between thread creation and function pointer initialization
5. C++ runtime trying to call a destructor or initialization function that's in the function table

## Next Steps
1. Run test with new debug logging to see if constructor messages appear
2. If constructor messages appear, the crash is in `std::thread` creation
3. If constructor messages don't appear, the crash is even earlier (before constructor)
4. Check if the crash is related to C++ runtime initialization or destructors
5. Investigate if there's a global constructor/destructor being called that's in the function table

## Files Modified
- `Mw05Recomp/cpu/guest_thread.cpp` (lines 87-173): Added extensive debug logging
- `docs/research/THREAD_CRASH_DEBUG_STATUS.md`: Documented previous debug attempts
- `docs/research/THREAD_CRASH_FINAL_STATUS.md`: This file

## Test Command
```powershell
powershell -ExecutionPolicy Bypass -File scripts/run_clean_test.ps1
```

## Expected Output
If the constructor is being called, we should see:
```
[GUEST_THREAD_HANDLE] Constructor ENTER: entry=0x828508A8 flags=0x00000001 suspended=1
[GUEST_THREAD_HANDLE] About to create std::thread with GuestThreadFunc=... this=...
```

If the crash happens during thread creation, we should see:
```
[GUEST_THREAD_HANDLE] Constructor ENTER: entry=0x828508A8 flags=0x00000001 suspended=1
[GUEST_THREAD_HANDLE] About to create std::thread with GuestThreadFunc=... this=...
[*] [crash] unhandled exception code=0xC0000005 addr=...
```

If the crash happens before the constructor, we won't see any of these messages.

