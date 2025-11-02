# ROOT CAUSES AND PROPER FIXES

**Date**: 2025-11-02  
**Status**: WORKAROUNDS IN PLACE - ROOT CAUSES NOT FIXED

## Summary

The game currently requires `MW05_DEBUG_PROFILE=1` to work, which enables multiple environment variable workarounds. **These are NOT debug settings - they are WORKAROUNDS for underlying recompiler bugs.**

Disabling `MW05_DEBUG_PROFILE=0` causes:
- ❌ Memory leaks (PM4 commands not processed)
- ❌ Deadlocks (GPU wait commands never acknowledged)
- ❌ File I/O hangs (game stuck in initialization)
- ❌ Game never progresses to rendering (`draws=0`)

## ROOT CAUSE #1: Game Stuck in Init5 - Function Pointer Table Iterator Never Returns

### The Problem
The game is stuck in `sub_8262FC50` (Init5) and **NEVER RETURNS**. Init5 is a function pointer table iterator that calls each function in two tables. One of these functions is stuck in an infinite loop or waiting forever.

### Evidence
```
[MAIN-THREAD-ENTRY-OLD] Main thread entry 0x8262E9A8 called!
[MAIN-THREAD-INIT] Init1 0x82630068 called
[MAIN-THREAD-INIT] Init2 0x8262FDA8 called, r3=00000001
[MAIN-THREAD-INIT] Init3 0x826BE558 called
[MAIN-THREAD-INIT] Init4 0x8262FD30 called, r3=00000001
[MAIN-THREAD-INIT] Init5 0x8262FC50 called, r3=00000001  ← STUCK HERE!
[MAIN-THREAD-HEARTBEAT] tid=00008264 alive for 1 seconds
[MAIN-THREAD-HEARTBEAT] tid=00008264 alive for 2 seconds
...
(NO Init6 logs - Init5 never returns!)
(NO Init7 logs - never reached!)
(NO main loop logs - never reached!)
```

The main thread is ALIVE (heartbeat working) but stuck inside Init5. It never returns from Init5.

### Init5 Decompilation
```c
int sub_8262FC50()
{
  // First table: 0x828DF0FC to dword_828DF108
  for (v1 = 0x828DF0FC; v1 < dword_828DF108; v1++) {
    if (*v1) {
      result = (*v1)();  // Call function pointer
      if (result) return result;  // Early return if non-zero
    }
  }

  // Second table: 0x828D0010 to dword_828DF0F8
  for (v3 = 0x828D0010; v3 < dword_828DF0F8; v3++) {
    if (*v3 && *v3 != -1) {
      result = (*v3)(result);  // Call function pointer
    }
  }

  return 0;  // Success
}
```

One of the functions in these tables is stuck and never returns!

### Impact
- Game stuck in initialization forever
- Never reaches Init6 (region check)
- Never reaches main loop
- Never loads files
- Result: `draws=0` forever

### Current Workaround
**NONE** - This bug is NOT worked around by environment variables. The game is permanently stuck.

### Proper Fix
**Find which function in Init5's tables is stuck**:
1. Dump the function pointer tables at `0x828DF0FC-dword_828DF108` and `0x828D0010-dword_828DF0F8`
2. Add logging to Init5 to see which function is being called when it gets stuck
3. Identify the stuck function
4. Fix the stuck function (likely waiting for something that never happens)

### Files to Check
- `Mw05Recomp/cpu/mw05_main_thread_trace.cpp` - Main thread initialization tracing
- IDA decompilation of `sub_8262FC50` (Init5)
- Function pointer tables at `0x828DF0FC` and `0x828D0010`

---

## ROOT CAUSE #2: PM4 Buffer Mismatch

### The Problem
The game writes PM4 commands to the **System Command Buffer** (0x00F00000), but the PM4 parser and GPU command processing thread read from the **Ring Buffer** (0x001002E0).

This is a fundamental architectural mismatch.

### Evidence
```
Game writes PM4 → System Command Buffer (0x00F00000)
                         ↓
                         ❌ MISMATCH!
                         ↓
PM4 parser reads ← Ring Buffer (0x001002E0) ← Empty/DEADBEEF
```

### Impact
- PM4 commands written by game are never processed
- GPU command processing thread sees empty ring buffer
- No draw commands executed
- Result: `draws=0`

### Current Workarounds
1. **`MW05_PM4_SYSBUF_TO_RING=1`** - Copies system buffer → ring buffer every frame
   - Adds massive overhead (64KB memcpy per frame)
   - Causes FPS drops
   - Masks the real problem

2. **`MW05_PM4_SYSBUF_WATCH=1`** - Watches for writes to system buffer
   - Detects when game writes PM4 commands
   - Triggers copy to ring buffer

3. **`MW05_FORCE_ACK_WAIT=1`** - Fakes GPU acknowledgments
   - PM4 WAIT commands never complete naturally
   - Forces acknowledgment to prevent deadlocks

### Proper Fix
**Option A**: Make PM4 parser read from system buffer
- Modify `PM4_ScanRingBuffer()` to also scan system buffer
- Or replace ring buffer scanning with system buffer scanning
- Update GPU command processing thread to read from system buffer

**Option B**: Redirect game writes to ring buffer
- Intercept `VdGetSystemCommandBuffer()` to return ring buffer address
- Game writes directly to ring buffer
- No copying needed

**Option C**: Fix the recompiler
- Investigate why game uses system buffer instead of ring buffer
- May be a recompilation artifact
- Check if original Xbox 360 game uses ring buffer correctly

### Files to Check
- `Mw05Recomp/gpu/pm4_parser.cpp` - PM4 command parser
- `Mw05Recomp/kernel/system_threads.cpp` - GPU command processing thread
- `Mw05Recomp/kernel/imports.cpp` - VdGetSystemCommandBuffer, VdInitializeRingBuffer
- `Mw05Recomp/gpu/video.cpp` - PM4 buffer copying workaround (lines 3383-3521)

---

## ROOT CAUSE #3: File I/O - Game Stuck in Initialization

### The Problem
The game never calls the loader dispatcher, so StreamBridge is never triggered and no files are loaded.

### Evidence
```
[FAIL] NO StreamBridge activity - game is not trying to load files!
[INFO] NO sentinel writes detected (0x0A000000)
```

### Impact
- No files loaded (GLOBALMEMORYFILE.BIN, textures, models, etc.)
- Game cannot progress to rendering without assets
- Result: `draws=0`

### Current Workaround
**`MW05_STREAM_BRIDGE=1`** - Enables StreamBridge file I/O interception
- Ready to intercept file loads
- But never triggered because game stuck in init
- **This workaround doesn't actually help!**

### Proper Fix
**Fix ROOT CAUSE #1 first!**

The file I/O issue is a **symptom** of the main loop bug. Once the main loop is fixed and the game progresses past initialization, it will naturally call the loader dispatcher and load files.

No separate fix needed - just fix the main loop bug.

---

## Action Plan

### Priority 1: Fix Main Loop Bug (ROOT CAUSE #1)
This is the **critical blocker** that prevents everything else from working.

**Steps**:
1. Decompile `sub_82441CF0` using IDA Pro API
2. Analyze the loop structure and identify why it exits early
3. Create manual override using `PPC_FUNC_IMPL` + `PPC_FUNC` pattern
4. Test that main loop runs continuously
5. Verify game progresses to file loading

### Priority 2: Fix PM4 Buffer Mismatch (ROOT CAUSE #2)
Once main loop is fixed, this becomes the next blocker.

**Steps**:
1. Modify PM4 parser to read from system buffer instead of ring buffer
2. Remove `MW05_PM4_SYSBUF_TO_RING` workaround
3. Remove `MW05_FORCE_ACK_WAIT` workaround
4. Test that PM4 commands are processed correctly
5. Verify `draws > 0`

### Priority 3: Remove All Workarounds
Once root causes are fixed, clean up the codebase.

**Steps**:
1. Remove all `MW05_*` environment variable checks
2. Remove `MwApplyDebugProfile()` function
3. Remove workaround code from `video.cpp`, `pm4_parser.cpp`, etc.
4. Test that game works without any environment variables
5. Document the fixes in AGENTS.md

---

## Current Status

**Game State**: Stuck in initialization, main loop not looping  
**Workarounds Active**: 15+ environment variables  
**Root Causes Fixed**: 0 / 3  
**Proper Fixes Needed**: All of them

**Next Step**: Fix the main loop bug (ROOT CAUSE #1) - this is the critical blocker.

