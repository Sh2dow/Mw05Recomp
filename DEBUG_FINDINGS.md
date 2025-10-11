# Debug Findings - Game Stuck in Sleep Loop

## Summary

The game is running but stuck in a loop, not progressing to the point where it loads files or issues draw commands.

## Current State (After Fixes)

- **Import Coverage**: 388/719 (54%) imports patched (+20 from registering sub_824411E0 wrapper)
- **Graphics Callbacks**: 2,049 invocations in 30 seconds
- **PM4 Scans**: 2 scans, both showing draws=0
- **File I/O**: **ZERO** file operations (NtCreateFile/NtOpenFile/NtReadFile never called)
- **Sleep Calls**: 27,855 calls to KeDelayExecutionThread in 30 seconds
- **Threads Created**: 3 threads (entries: 0x828508A8, 0x82812ED0, 0x82849D40)
- **Thread 0x824411E0**: **NEVER CREATED** - This is the thread that should set the unblock flag!

## Top Functions Called (30 seconds)

| Function | Calls | Notes |
|----------|-------|-------|
| Store64BE_W | 128,103 | Memory writes |
| Store8BE_W | 16,238 | Memory writes |
| sub_8262F2A0 | 9,287 | Main loop function |
| KeDelayExecutionThread | 9,285 | Sleeping |
| sub_825979A8 | 3,987 | Graphics callback |
| RtlEnterCriticalSection | 2,484 | Lock acquisition |
| RtlLeaveCriticalSection | 2,484 | Lock release |
| VdCallGraphicsNotificationRoutines | 1,994 | Graphics notifications |

## Critical Observations

### 1. No File I/O
The game has **NOT** called any file I/O functions:
- NtCreateFile: 0 calls
- NtOpenFile: 0 calls
- NtReadFile: 0 calls
- NtWriteFile: 0 calls

This is abnormal - the game should be loading textures, models, sounds, etc.

### 2. Stuck in Sleep Loop
The game is calling `KeDelayExecutionThread` 9,285 times in 30 seconds (310 times/second).
This suggests the game is in a tight loop waiting for something.

### 3. Graphics Callbacks Active
The graphics callback (`sub_825979A8`) is being invoked 3,987 times, which is good.
However, it's not issuing any draw commands.

### 4. Minimal Xam Usage
Only 3 calls to `XamContentCreateEx` - the content system is barely being used.

## Comparison with Xenia

In Xenia's log:
- Import table is processed (line 909-1110)
- Game loads title name "NFS Most Wanted" (line 1122-1123)
- VD notify callback is invoked (line 35788+)
- **NEW THREAD** is created for rendering
- Draw commands are issued

In our implementation:
- ✅ Import table is processed (368/719 patched)
- ✅ Graphics callbacks are invoked
- ❌ No new threads created for rendering
- ❌ No file I/O
- ❌ No draw commands

## Hypothesis

The game appears to be waiting for one of the following:

1. **User Input** - Maybe the game needs a button press to start?
2. **Missing Thread** - Maybe a critical thread isn't being created?
3. **Missing Import** - Maybe a critical function is stubbed and returning failure?
4. **Synchronization** - Maybe the game is waiting on a semaphore/event that never gets signaled?
5. **Content System** - Maybe XamContent* functions need to work properly?

## Missing Imports Being Called

Top missing imports (all called 2 times):
- XamGetPrivateEnumStructureFromHandle
- XMsgSystemProcessCall
- NetDll_XNetCleanup
- NetDll_XNetCreateKey
- NetDll_XNetRandom
- XamCreateEnumeratorHandle
- RtlCompareMemory
- KeSetDisableBoostThread
- ObOpenObjectByPointer
- ObLookupThreadByThreadId

Most of these are networking (NetDll_*) which shouldn't be critical for offline play.

## Errors in Trace Log

Only 6 errors found:
```
HOST.825968B0.invalid_r3 r3=00000000 - attempting to seed
HOST.825968B0.still_invalid r3=00000000 - returning NULL
```

Function at `0x825968B0` is being called with invalid r3 (NULL pointer).
This happens 4 times.

## Next Steps

### Immediate Actions
1. ✅ Fix `run_minimal.ps1` to force Present (DONE)
2. Investigate why no file I/O is happening
3. Check if game needs user input to progress
4. Implement missing Xam* functions that might be blocking

### Investigation Needed
1. What is `sub_8262F2A0`? (main loop function)
2. What is `sub_825968B0`? (function with invalid r3 errors)
3. Why isn't the game creating new threads?
4. What triggers file I/O in the game?

### Functions to Implement
Priority order based on frequency:
1. XamGetPrivateEnumStructureFromHandle (2 calls)
2. XMsgSystemProcessCall (2 calls)
3. XamCreateEnumeratorHandle (2 calls)
4. RtlCompareMemory (2 calls) - already implemented but not in lookup table

## Tools Created

- `debug_blocking.ps1` - Automated debug script
- `tools/analyze_trace_functions.py` - Trace log analyzer
- `tools/analyze_sleep_pattern.py` - Sleep pattern analyzer
- `test_window_response.ps1` - Window responsiveness tester
- Updated `run_minimal.ps1` - Now forces Present to avoid stale image

## Files Modified

- `run_minimal.ps1` - Set MW05_FORCE_PRESENT=1
- `Mw05Recomp/main.cpp` - Added diagnostic logging to main loop and registered sub_824411E0 wrapper
- `Mw05Recomp/gpu/video.cpp` - Added diagnostic logging to Present function
- `Mw05Recomp/kernel/imports.cpp` - Removed conflicting stub functions
- `AGENTS.md` - Updated with current status
- `DEBUG_FINDINGS.md` - This document

## Window Responsiveness Investigation

### ✅ Confirmed Working
- Main event loop IS running (600+ iterations in 10 seconds)
- Present IS being called (multiple times per second)
- SDL events are being processed
- Renderer is initialized

### ⚠️ Issue
- Window shows **stale/garbage image** because no draws have been issued yet
- The backbuffer is not being cleared, so it shows uninitialized memory
- Game is stuck in sleep loop and hasn't progressed to rendering

### 🎯 Solution Needed
Either:
1. Clear the backbuffer to black on each Present (cosmetic fix)
2. Fix the root cause - get the game to progress past the sleep loop and issue draw commands (real fix)

