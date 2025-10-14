# MW05 Recompilation Progress Summary

## Current Status: System Threads Implemented, Game Still Not Rendering

### What We've Accomplished

1. ✅ **Fixed PPC Recompiler Bug**
   - Fixed `divw` instruction to properly sign-extend division results to 64 bits
   - Regenerated all 106 PPC source files with the fixed recompiler
   - Build completes successfully with no linker errors

2. ✅ **Implemented System Threads**
   - Created `Mw05Recomp/kernel/system_threads.cpp`
   - Implemented 5 system threads that Xenia creates before game module loads:
     * GPU Commands thread
     * GPU Frame limiter thread
     * XMA Decoder thread
     * Audio Worker thread
     * Kernel Dispatch thread
   - Threads are created successfully and running
   - Added to CMakeLists.txt and integrated into main.cpp

3. ✅ **Graphics System Working**
   - Heap-based context allocation working correctly
   - Nested structure pointers using big-endian storage for PPC code
   - PM4 command buffer scanning active
   - VBlank interrupt system working
   - MicroIB interpreter implemented and ready

4. ✅ **Import Table Patching**
   - 388/719 imports (54%) successfully patched
   - 232 __imp__ functions in lookup table
   - All critical kernel functions (Ke*, Nt*, Ex*, Rtl*) implemented

### Current Problem: Game Stuck in Early Initialization

**Symptoms**:
- Game runs but never calls `VdSetGraphicsInterruptCallback`
- VBlank callback is NOT registered (cb=0x00000000, ctx=0x00000000)
- Only 1 game thread created (should be 9 total according to Xenia)
- No file I/O operations (NtCreateFile/NtOpenFile/NtReadFile never called)
- Main loop not running (only 2 sleeps in 60 seconds vs 149,148 in Xenia)
- No draw commands issued
- PM4 scans show draws=0

**Root Cause Analysis**:
The system threads we created are stub threads that only sleep. They don't provide any actual functionality. The game is likely waiting for one of these threads to provide a service before it progresses.

In Xenia, these threads are part of the Xbox kernel infrastructure and provide actual services:
- GPU Commands thread: Processes GPU command submissions
- XMA Decoder thread: Handles audio decoding
- Audio Worker thread: Manages audio playback
- Kernel Dispatch thread: Handles kernel-level dispatching
- GPU Frame limiter thread: Controls frame pacing

Our stub threads just sleep in a loop and don't do anything, so the game is stuck waiting for these services to become available.

### Comparison with Xenia

**Xenia (Working)**:
- Creates 9 threads total (5 system + 4 game)
- Processes import table: 193 xboxkrnl imports patched
- Game sleeps 149,148 times (normal behavior)
- VD notify callback invoked, NEW THREAD created
- First draw command issued after extensive initialization

**Our Implementation (Current)**:
- Creates 6 threads total (5 system + 1 game)
- Processes import table: 388/719 imports patched
- Game sleeps only 2 times (stuck)
- VD notify callback NEVER registered
- No draw commands ever issued

### Next Steps to Fix

**Option 1: Implement Actual Thread Functionality** (Complex)
- Implement GPU command processing in GPU Commands thread
- Implement XMA audio decoding in XMA Decoder thread
- Implement audio playback in Audio Worker thread
- Implement kernel dispatching in Kernel Dispatch thread
- This is a lot of work and requires deep understanding of Xbox 360 kernel

**Option 2: Find What Game is Waiting For** (Recommended)
- Add detailed logging to identify what the game is waiting for
- Check if game is waiting on a specific synchronization primitive
- Check if game is waiting for a specific kernel call to complete
- Implement minimal functionality to unblock the game

**Option 3: Force Graphics Callback Registration** (Workaround)
- We already tried this with `MW05_FORCE_GFX_NOTIFY_CB` environment variable
- It worked in previous tests but game still didn't progress
- This is a band-aid solution that doesn't address the root cause

### Files Modified in This Session

1. `Mw05Recomp/kernel/system_threads.cpp` (NEW)
   - Implements stub system threads
   - Threads sleep in a loop but don't provide actual functionality

2. `Mw05Recomp/main.cpp`
   - Added call to `Mw05CreateSystemThreads()` before starting guest thread
   - System threads are created early in initialization

3. `Mw05Recomp/CMakeLists.txt`
   - Added `kernel/system_threads.cpp` to build sources

4. `test_longer_run.ps1` (NEW)
   - Test script that runs game for 60 seconds and captures detailed stats
   - Analyzes thread creation, file I/O, VdSwap calls, PM4 scans, draws, etc.

### Key Findings from Testing

1. **System threads are created successfully**
   - All 5 threads start and run
   - Logs show: `[SYSTEM-THREAD] GPU Commands thread started`, etc.

2. **VBlank callback is NOT registered**
   - `[VBLANK-ISR-STATUS] tick=3600 cb=00000000 ctx=00000000`
   - Game never calls `VdSetGraphicsInterruptCallback`

3. **Game is stuck waiting**
   - Only 2 sleep calls in 60 seconds
   - No file I/O operations
   - No additional threads created
   - No progress toward rendering

### Recommended Immediate Action

1. **Add detailed logging to identify blocking point**
   - Log all kernel calls with timestamps
   - Log all thread synchronization operations
   - Log all memory allocations
   - Identify where the game is stuck

2. **Compare with Xenia logs in detail**
   - Identify the exact sequence of calls Xenia makes
   - Identify which calls we're missing
   - Implement the missing calls

3. **Investigate thread synchronization**
   - Check if game is waiting on a mutex, semaphore, or event
   - Check if game is waiting for a specific thread to signal completion
   - Implement minimal synchronization to unblock the game

### Environment Variables for Testing

```powershell
$env:MW05_FAST_BOOT = "1"                          # Fast boot to skip delays
$env:MW05_UNBLOCK_MAIN = "1"                       # Unblock main thread (may cause issues)
$env:MW05_BREAK_82813514 = "1"                     # Break worker thread loop
$env:MW05_BREAK_WAIT_LOOP = "1"                    # Break wait loop
$env:MW05_FORCE_PRESENT = "1"                      # Force host to present frames
$env:MW05_FORCE_GFX_NOTIFY_CB = "1"                # Force graphics callback registration
$env:MW05_FORCE_GFX_NOTIFY_CB_CTX = "0x40007180"   # Graphics callback context address
$env:MW05_FORCE_GFX_NOTIFY_CB_DELAY_TICKS = "350"  # Delay before forcing callback
```

### Conclusion

We've made significant progress:
- Fixed critical recompiler bugs
- Implemented system threads infrastructure
- Graphics system is ready and waiting
- Import table is mostly patched

However, the game is stuck in early initialization because our stub system threads don't provide the actual services the game needs. The next step is to identify exactly what service the game is waiting for and implement minimal functionality to unblock it.

The game is SO CLOSE to rendering - all the infrastructure is in place, we just need to figure out what's blocking it from progressing to the rendering phase.

