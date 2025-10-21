# No Draws Investigation - Deep Analysis

**Date**: 2025-10-21
**Status**: ROOT CAUSE IDENTIFIED - VdSwap Not Being Called
**Priority**: CRITICAL - Investigate why render thread isn't calling VdSwap

## ROOT CAUSE IDENTIFIED

**The game is NOT calling VdSwap to submit PM4 commands!**

### Evidence from Console Log Analysis (2025-10-21)
1. **Ring Buffer is Empty** - All PM4 packets are zeros (header=00000000, raw=00000000)
2. **VdSwap is Patched** - Import table shows VdSwap is correctly patched at 0x82000A1C and 0x828AA03C
3. **VdSwap is NOT Called** - No "HOST.VdSwap" messages in console log after 10+ minutes
4. **PM4_ScanLinear is Active** - Host is scanning ring buffer (107,668 bytes/frame)
5. **BeginCommandList is Called** - Host rendering infrastructure is working

### What This Means
The render thread is either:
- **Not executing** the draw submission code that calls VdSwap
- **Waiting** for some condition before calling VdSwap
- **Stuck in a loop** before reaching VdSwap
- **Taking a different code path** that doesn't call VdSwap

## Executive Summary

The game runs stable for 10+ minutes without crashing, but **NO DRAW COMMANDS** are being issued. PM4 command processing is active (107,668 bytes/frame), but `draws=0` in all scans.

**Key Finding**: The ring buffer is being CLEARED but not WRITTEN TO. VdSwap is NOT being called by the game.

## Current State

### What's Working ✅
1. **Game Stability** - Runs 10+ minutes without crashing
2. **PM4 Processing** - 114,616 bytes/frame being scanned
3. **Graphics Callbacks** - VBlank ISR invokes callback at 0x825979A8
4. **Ring Buffer Setup** - Base: 0x000202E0, Size: 65536 bytes
5. **File I/O** - Streaming bridge loading resources (379+ operations)
6. **All Threads Running** - 12 threads created and active

### What's NOT Working ❌
1. **VdSwap Not Called** - Game is not submitting PM4 commands via VdSwap
2. **No Draw Commands** - draws=0 after 10+ minutes
3. **Empty Ring Buffer** - Only 16 non-zero DWORDs out of 16384 (0.098%)
4. **No TYPE3 Draw Opcodes** - No 0x22 (DRAW_INDX) or 0x36 (DRAW_INDX_2) detected

## Next Steps - Investigate VdSwap Call Path

### Phase 1: Trace Render Thread Execution (IMMEDIATE)

**Goal**: Understand why VdSwap is not being called

**Actions**:
1. Add logging to render thread entry point (0x825AA970)
2. Search for VdSwap call sites in recompiled code
3. Add logging before VdSwap calls to trace execution path
4. Check if render thread is reaching VdSwap call sites
5. Compare with Xenia's execution to see when VdSwap is called

**Expected Behavior**:
- Render thread should execute its main loop
- Should build PM4 commands in ring buffer or system command buffer
- Should call VdSwap to submit commands to GPU
- VdSwap should trigger PM4_OnRingBufferWrite() to scan commands

### Phase 2: Check Render Thread State

**Goal**: Verify render thread is not stuck or waiting

**Actions**:
1. Add logging to render thread main loop
2. Check if thread is waiting on events/semaphores
3. Check if thread is stuck in infinite loop
4. Compare thread execution with Xenia

**Expected Behavior**:
- Render thread should be actively executing
- Should not be blocked on synchronization primitives
- Should progress through initialization to rendering phase

### Phase 3: Investigate Graphics State

**Goal**: Check if graphics state is preventing VdSwap calls

**Actions**:
1. Check if graphics context is fully initialized
2. Check if render targets are set up
3. Check if shaders are loaded and bound
4. Check if game is waiting for resource loading to complete

**Expected Behavior**:
- Graphics context should be initialized
- Render targets should be configured
- Shaders should be loaded
- Game should have all resources needed for rendering

## PM4 Opcode Analysis

### Expected Draw Opcodes (NOT SEEN):
```
0x22 (PM4_DRAW_INDX)      - Draw indexed primitives
0x36 (PM4_DRAW_INDX_2)    - Draw indexed primitives (variant)
```

### Actual Opcodes Detected:
From PM4_DumpOpcodeHistogram(), we need to check what opcodes ARE being processed.

**Action Required**: Run game with `MW05_PM4_TRACE=1` and check trace log for:
```
HOST.PM4.OPC[XX]=count
```

This will tell us what TYPE3 commands the game IS issuing.

## Root Cause Hypotheses

### Hypothesis 1: Game Waiting for Resource Loading
**Evidence**:
- File I/O is working (379+ StreamBridge operations)
- Loading `game:\GLOBAL\GLOBALMEMORYFILE.BIN` (6.3 MB)
- Game may need to load shaders/textures before issuing draws

**Test**:
1. Monitor file I/O completion
2. Check if game loads shader files (.xvu, .xpu)
3. Compare with Xenia's file loading sequence

**Expected Behavior**:
- Xenia loads resources BEFORE issuing first draw
- Our implementation should do the same

### Hypothesis 2: Missing Graphics State Initialization
**Evidence**:
- PM4 packets are being processed (114,616 bytes/frame)
- But ring buffer is mostly empty (99.9% zeros)
- Game may be waiting for some graphics state to be set

**Test**:
1. Check PM4 TYPE0 packets (register writes)
2. Look for render target setup
3. Look for viewport/scissor setup
4. Compare with Xenia's PM4 sequence

**Expected Behavior**:
- Game should write TYPE0 packets to set up graphics state
- Then issue TYPE3 draw commands

### Hypothesis 3: Render Thread Not Executing Draw Path
**Evidence**:
- All 12 threads are running
- Graphics callbacks are being invoked
- But no draws are being issued

**Test**:
1. Add logging to render thread entry point (0x825AA970)
2. Check if render thread is reaching draw submission code
3. Compare thread execution with Xenia

**Expected Behavior**:
- Render thread should execute draw submission loop
- Should write PM4 commands to ring buffer

### Hypothesis 4: Missing Synchronization Event
**Evidence**:
- Game runs for 10+ minutes without progressing
- May be waiting for some event/signal

**Test**:
1. Check for Wait() calls that never complete
2. Look for event signals that aren't being triggered
3. Compare event flow with Xenia

**Expected Behavior**:
- Game should signal events to trigger rendering
- Render thread should wake up and issue draws

## Investigation Plan

### Phase 1: PM4 Opcode Histogram (IMMEDIATE)
**Goal**: Understand what PM4 commands ARE being processed

**Steps**:
1. Run game with `MW05_PM4_TRACE=1`
2. Let it run for 30 seconds
3. Check trace log for `HOST.PM4.OPC[XX]=count`
4. Identify which TYPE3 opcodes are present
5. Compare with Xenia's opcode histogram

**Expected Output**:
```
HOST.PM4.OPC[00]=12345    # NOP commands
HOST.PM4.OPC[10]=678      # Some other command
HOST.PM4.OPC[22]=0        # DRAW_INDX (should be >0 if working)
HOST.PM4.OPC[36]=0        # DRAW_INDX_2 (should be >0 if working)
```

### Phase 2: File I/O Completion Check
**Goal**: Verify all required resources are loaded

**Steps**:
1. Monitor StreamBridge operations
2. Check if shader files are loaded (.xvu, .xpu)
3. Check if texture files are loaded
4. Compare with Xenia's file loading sequence

**Expected Behavior**:
- Game should load shaders before issuing draws
- File I/O should complete before rendering starts

### Phase 3: Render Thread Execution Trace
**Goal**: Verify render thread is executing draw submission code

**Steps**:
1. Add logging to render thread entry (0x825AA970)
2. Add logging to draw submission functions
3. Check if render thread reaches draw code
4. Compare with Xenia's thread execution

**Expected Behavior**:
- Render thread should execute draw submission loop
- Should write PM4 commands to ring buffer

### Phase 4: Graphics State Verification
**Goal**: Verify graphics state is properly initialized

**Steps**:
1. Check PM4 TYPE0 packets (register writes)
2. Verify render target is set
3. Verify viewport/scissor are set
4. Verify shaders are bound
5. Compare with Xenia's PM4 sequence

**Expected Behavior**:
- Game should set up graphics state via TYPE0 packets
- Then issue TYPE3 draw commands

## Diagnostic Commands

### Run with PM4 Tracing
```powershell
$env:MW05_PM4_TRACE = "1"
$env:MW05_DEBUG_PM4 = "3"
python scripts/auto_handle_messageboxes.py --duration 30
```

### Check Opcode Histogram
```powershell
Get-Content out/build/x64-Clang-Debug/Mw05Recomp/mw05_host_trace.log | Select-String "HOST.PM4.OPC"
```

### Check File I/O
```powershell
Get-Content out/build/x64-Clang-Debug/Mw05Recomp/mw05_host_trace.log | Select-String "StreamBridge"
```

### Check Render Thread
```powershell
Get-Content out/build/x64-Clang-Debug/Mw05Recomp/mw05_host_trace.log | Select-String "825AA970"
```

## Performance Considerations

**Current Overhead**:
- PM4 scanning: 114,616 bytes/frame = ~1.8 MB/sec
- Trace logging: 572 MB in 8 minutes = ~1.2 MB/sec
- Total I/O: ~3 MB/sec (acceptable)

**Optimization Opportunities**:
1. Reduce PM4 scan frequency once draws appear
2. Use verbosity control to reduce trace spam
3. Disable unnecessary logging after debugging

## Next Steps

1. **IMMEDIATE**: Run Phase 1 (PM4 Opcode Histogram)
2. **PRIORITY**: Identify which TYPE3 opcodes ARE being processed
3. **INVESTIGATE**: Why DRAW_INDX/DRAW_INDX_2 are not appearing
4. **COMPARE**: With Xenia's PM4 sequence to find differences
5. **FIX**: Root cause blocking draw command submission

## Success Criteria

**Milestone 1**: Identify PM4 opcodes being processed
- [ ] Run with PM4 tracing enabled
- [ ] Collect opcode histogram
- [ ] Compare with Xenia

**Milestone 2**: Understand why no draws
- [ ] Identify missing graphics state
- [ ] Identify missing synchronization
- [ ] Identify missing resource loading

**Milestone 3**: Get first draw command
- [ ] Fix root cause blocking draws
- [ ] Verify DRAW_INDX or DRAW_INDX_2 appears
- [ ] Verify draw count > 0

**Milestone 4**: Rendering works
- [ ] Draw commands execute successfully
- [ ] Graphics appear on screen
- [ ] Game progresses to menu/gameplay

## References

- [PM4 Parser Implementation](../../Mw05Recomp/gpu/pm4_parser.cpp)
- [PM4 Opcode Definitions](../../Mw05Recomp/gpu/pm4_parser.cpp#L32-L55)
- [Ring Buffer Setup](../../Mw05Recomp/kernel/imports.cpp#L1471-L1491)
- [NO_DRAWS_ROOT_CAUSE.md](NO_DRAWS_ROOT_CAUSE.md) - Previous investigation
- [AGENTS.md](../../AGENTS.md#L199-L219) - Next steps section

