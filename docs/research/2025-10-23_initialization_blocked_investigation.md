# MW05 Initialization Blocked - Root Cause Investigation
**Date**: 2025-10-23  
**Status**: ROOT CAUSE IDENTIFIED - Game stuck in initialization, never progresses to rendering

## Executive Summary

The game is **stuck in initialization phase** and never progresses to rendering. This is evidenced by:
- **NO draw commands issued** (`draws=0` throughout 150-second run)
- **Static PM4 buffer** (opcode 0x3E count never changes from 2048)
- **Callback structure never initializes naturally** (work_func stays at 0x00000000)
- **NO file I/O operations** (no NtCreateFile/NtReadFile calls in logs)

## Critical Findings

### 1. Callback Parameter Structure Not Initialized

**Address**: `0x82A2B318`  
**Expected**: Work function pointer at offset +16 (0x10) should be `0x82441E58`  
**Actual**: Stays at `0x00000000` for ticks 0-295

From `mw05_trace_threads.cpp` lines 309-372:
```cpp
uint32_t callback_param_addr = 0x82A2B318;
uint32_t work_func_ptr = callback_param_u32[16/4];  // +0x10 (16) - work function pointer

if (work_func_ptr == 0 || work_func_ptr == 0xFFFFFFFF) {
    fprintf(stderr, "[FORCE_WORKERS] Callback parameter structure NOT initialized yet (work_func=0x%08X)\n", work_func_ptr);
    return;  // Can't create worker threads yet
}
```

**Current Workaround**: `FORCE_WORKERS` code forcibly initializes this at tick 296, but this doesn't solve the underlying problem.

### 2. NO File I/O Operations

**Evidence from logs**:
- NO `NtCreateFile` calls logged
- NO `NtReadFile` calls logged  
- NO file paths like `game:\GLOBAL\GLOBALMEMORYFILE.BIN` appear
- XamContent functions are imported but never called

**Expected behavior**: Game should load resources during initialization:
- Global memory files
- Texture packages
- Shader caches
- Configuration files

### 3. PM4 Command Buffer is Static

**Evidence**:
- Opcode 0x3E appears exactly **2048 times** in every histogram dump
- This count **NEVER changes** throughout the 150-second run
- NO new PM4 commands are being written to the buffer
- NO draw commands (DRAW_INDX 0x22 or DRAW_INDX_2 0x36) ever appear

**Implication**: The game's render thread is not writing new commands, suggesting it's waiting for initialization to complete.

### 4. Graphics Initialization Appears Complete

**Evidence from logs** (lines 4011-4015):
```
[GFX-CTX] Initialized spinlock at context+0x2898
[GFX-CTX] Initialized context members: +0x3CEC, +0x3CF0, +0x3CF4, +0x3CF8, +0x3CFC
[GFX-CTX] Set VdGlobalDevice and VdGlobalXamDevice to 0x00CDDEE0 (points to 0x00CC5EE0)
[GFX-CTX] Initialized static pointers: 0x101BE=0x00CDDEE0, 0x101BF=0x00CDDEE0
[GFX-CTX] Set fallback allocator at offset 0x3D0C to 0x00CDDF20
```

**Implication**: Graphics subsystem is initialized, but game logic is blocked waiting for something else.

## Root Cause Analysis

### What's Missing?

The game appears to be waiting for **one or more of these conditions**:

1. **Profile/Save System Initialization**
   - XamNotifyCreateListener was called (line 1484: `handle=0xA0000000 areas=0x5`)
   - But notification callbacks may not be firing correctly
   - Game might be waiting for profile manager callback

2. **Resource Loading Completion**
   - NO file I/O operations are happening
   - Game might be stuck waiting for file system to become ready
   - Possible missing Xbox kernel file system initialization

3. **Scheduler/Worker Thread Initialization**
   - Callback parameter structure at 0x82A2B318 never initializes naturally
   - This structure is critical for worker thread creation
   - Something should write work_func=0x82441E58 but doesn't

4. **Main Thread Progression**
   - Main thread might be blocked in initialization loop
   - Waiting for flag/event that never gets set
   - MW05_UNBLOCK_MAIN workaround suggests main thread blocking issue

## Comparison with Working Xenia Session

**What Xenia does differently**:
1. **Full Xbox kernel implementation** - all notification callbacks work
2. **Complete file system** - game can load resources
3. **Proper scheduler initialization** - callback structures get initialized naturally
4. **Event signaling** - all kernel events fire correctly

**What we're missing**:
1. Some kernel functions are stubs that don't trigger proper callbacks
2. File system might not be fully initialized
3. Notification system might not be routing callbacks correctly
4. Some initialization sequence is broken or incomplete

## Investigation Plan

### Priority 1: File I/O Investigation
**Goal**: Determine why NO file I/O operations are happening

**Actions**:
1. Add detailed logging to NtCreateFile/NtReadFile implementations
2. Check if file system is initialized (VdGlobalDevice, VdGlobalXamDevice)
3. Verify game:\\ path mapping is working
4. Look for file I/O calls that might be failing silently

### Priority 2: Notification System Investigation
**Goal**: Verify XamNotifyCreateListener callbacks are working

**Actions**:
1. Add logging to notification callback dispatch
2. Check if notification areas 0x5 are being triggered
3. Verify notification listener handle 0xA0000000 is valid
4. Look for missing notification types

### Priority 3: Callback Structure Initialization
**Goal**: Find what naturally initializes 0x82A2B318 structure

**Actions**:
1. Search for writes to 0x82A2B318 in game code
2. Add memory watchpoint for this address
3. Trace backwards from work_func field to find initialization function
4. Check if this is part of profile manager or scheduler init

### Priority 4: Main Thread Analysis
**Goal**: Determine what main thread is waiting for

**Actions**:
1. Add detailed logging to main thread loop
2. Check what condition it's polling
3. Verify MW05_UNBLOCK_MAIN workaround is still needed
4. Find natural trigger for main thread progression

## Proposed Solutions

### Solution 1: Fix File System Initialization (RECOMMENDED)
**Rationale**: NO file I/O is the most obvious missing piece

**Implementation**:
1. Verify VdGlobalDevice/VdGlobalXamDevice are properly initialized
2. Check game:\\ path mapping in file system
3. Add detailed logging to all file I/O kernel functions
4. Ensure file system is ready before game entry point

**Expected Result**: Game starts loading resources, progresses through initialization

### Solution 2: Fix Notification Callbacks
**Rationale**: Profile manager might be waiting for notification

**Implementation**:
1. Verify XamNotifyCreateListener implementation
2. Ensure notification callbacks are dispatched correctly
3. Check if notification areas 0x5 need special handling
4. Add logging to track notification flow

**Expected Result**: Profile manager completes, game progresses

### Solution 3: Trace Callback Structure Initialization
**Rationale**: Find what naturally writes to 0x82A2B318

**Implementation**:
1. Add memory watchpoint for 0x82A2B318
2. Log all writes to this address
3. Trace backwards to find initialization function
4. Implement missing initialization if needed

**Expected Result**: Callback structure initializes naturally, worker threads created

## Next Steps

1. **Immediate**: Add comprehensive file I/O logging
2. **Short-term**: Investigate notification system
3. **Medium-term**: Trace callback structure initialization
4. **Long-term**: Compare with Xenia to find all missing pieces

## References

- `Mw05Recomp/cpu/mw05_trace_threads.cpp` - Worker thread creation logic
- `Mw05Recomp/kernel/imports.cpp` - Kernel function implementations
- `traces/auto_test_stderr.txt` - Test run logs showing no draws
- `docs/research/2025-10-22_no_draws_investigation.md` - Previous investigation

