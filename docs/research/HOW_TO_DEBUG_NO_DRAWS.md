# How to Debug "No Draws" Issue - Practical Guide

**Date**: 2025-10-21  
**Issue**: Game runs stable for 10+ minutes but draws=0 (no rendering)  
**Root Cause**: VdSwap is NOT being called by the game

## Quick Start - Debug Console

1. **Launch the game**
2. **Press ` (backtick) or F1** to open debug console
3. **Type commands** to investigate

## Investigation Workflow

### Step 1: Check Current Status

```
> status
Graphics verbosity: 1
PM4 verbosity: 1
Kernel verbosity: 1
Thread verbosity: 1
Heap verbosity: 1
File I/O verbosity: 1
VdSwap tracing: OFF
PM4 tracing: OFF
```

### Step 2: Enable VdSwap Tracing

```
> trace.vdswap on
VdSwap tracing enabled

> vdswap.log
Will log next 10 VdSwap calls with full context
```

**Expected**: If VdSwap is being called, you'll see log messages in console output  
**Actual**: NO messages = VdSwap is NOT being called (this is the problem!)

### Step 3: Check PM4 Ring Buffer

```
> pm4.dump 100
Dumped last 100 PM4 packets to console

> pm4.stats
PM4 Statistics:
  Total packets: 7,500,000
  TYPE3 packets: 20,437
  Draw commands: 0
  Ring buffer writes: 0
  Last write: NEVER
```

**Analysis**: 
- Ring buffer writes = 0 means game is NOT writing to PM4 buffer
- This confirms VdSwap is not being called (VdSwap submits PM4 commands)

### Step 4: Check PM4 Opcodes

```
> pm4.opcodes
PM4 Opcode Histogram:
  0x00 (NOP): 7,479,563 (99.7%)
  0x10 (REG_WRITE): 20,437 (0.3%)
  0x22 (DRAW_INDX): 0 (0.0%)
  0x36 (DRAW_INDX_2): 0 (0.0%)
```

**Analysis**:
- Only NOP and REG_WRITE commands (setup, no draws)
- NO draw commands (DRAW_INDX, DRAW_INDX_2)
- Game is in initialization phase

### Step 5: Check Thread Status

```
> thread.list
Thread List:
  #1 (0x828508A8): RUNNING - Main thread
  #2 (0x82812ED0): RUNNING - Worker thread
  #3 (0x828508A8): RUNNING - Worker thread
  #4 (0x828508A8): RUNNING - Worker thread
  #5 (0x828508A8): RUNNING - Worker thread
  #6 (0x828508A8): RUNNING - Worker thread
  #7 (0x828508A8): RUNNING - Worker thread
  #8 (0x825AA970): RUNNING - Special thread
  #9 (0x82812ED0): RUNNING - Worker thread
  #10 (0x82812ED0): RUNNING - Worker thread
  #11 (0x82812ED0): RUNNING - Worker thread
  #12 (0x82812ED0): RUNNING - Worker thread
```

**Analysis**: All 12 threads running (good!)

### Step 6: Check Heap Status

```
> heap.stats
Heap Statistics:
  User Heap:
    Total: 2046.50 MB
    Allocated: 128.45 MB
    Free: 1918.05 MB
  Physical Heap:
    Total: 1536.00 MB
    Allocated: 361.23 MB
    Free: 1174.77 MB
```

**Analysis**: Plenty of memory available (good!)

## Using CDB/WinDbg for Deep Debugging

When debug console isn't enough, use external debugger:

### Launch with CDB

```batch
scripts\debug.cmd cdb
```

**CDB Commands**:
```
# Break on VdSwap
bp Mw05Recomp!VdSwap
g

# If breakpoint hits, examine call stack
k

# If breakpoint NEVER hits, that's the problem!
# VdSwap is not being called by the game
```

### Launch with WinDbg

```batch
scripts\debug.cmd windbg
```

**WinDbg Commands**:
```
# Break on VdSwap
bp Mw05Recomp!VdSwap
g

# Break on present callback (sub_82598A20)
bp Mw05Recomp!sub_82598A20
g

# When breakpoint hits, step through to see if VdSwap is called
t
```

## Root Cause Analysis

### What We Know

1. ✅ Game runs stable for 10+ minutes
2. ✅ All 12 threads created and running
3. ✅ PM4 command processing active (114,616 bytes/frame)
4. ✅ File I/O working (streaming bridge loading resources)
5. ✅ Present callback IS being called (BeginCommandList messages)
6. ❌ VdSwap is NOT being called
7. ❌ Ring buffer is empty (all zeros)
8. ❌ No draw commands (draws=0)

### VdSwap Call Chain

```
Present Callback (sub_82598A20)
  └─> Line 6874 in ppc_recomp.72.cpp
      └─> __imp__VdSwap(ctx, base);
```

**Question**: Why is present callback NOT calling VdSwap?

### Hypothesis 1: Conditional Branch

Present callback might have a conditional branch that skips VdSwap:

```cpp
if (some_condition) {
    __imp__VdSwap(ctx, base);  // This line is NOT being reached
}
```

**How to Test**:
1. Add logging BEFORE VdSwap call site (line 6874)
2. Check if logging appears
3. If logging appears but VdSwap doesn't, there's a condition

### Hypothesis 2: Early Return

Present callback might return early before reaching VdSwap:

```cpp
if (error_condition) {
    return;  // Early return, VdSwap never called
}
__imp__VdSwap(ctx, base);  // Never reached
```

**How to Test**:
1. Add logging at START of present callback (line 6664)
2. Add logging at END of present callback (before VdSwap)
3. Compare counts - if START > END, there's an early return

### Hypothesis 3: Exception/Crash

Present callback might crash before reaching VdSwap:

```cpp
some_operation();  // Crashes here
__imp__VdSwap(ctx, base);  // Never reached
```

**How to Test**:
1. Use CDB/WinDbg to break on present callback
2. Step through line by line
3. See where execution stops

### Hypothesis 4: Wrong Function

Present callback might not be the right function:

```cpp
// We think VdSwap is called from sub_82598A20
// But maybe it's called from a DIFFERENT function
```

**How to Test**:
1. Search for ALL calls to VdSwap in generated code
2. Check if there are other call sites
3. Add breakpoints to all call sites

## Next Steps

### Immediate Actions

1. **Add logging to present callback**:
   - Log at START of function (line 6664)
   - Log BEFORE VdSwap call (line 6873)
   - Log AFTER VdSwap call (line 6875)

2. **Use CDB to break on present callback**:
   ```
   bp Mw05Recomp!sub_82598A20
   g
   ```

3. **Step through to VdSwap call**:
   ```
   t  # Step through each instruction
   ```

4. **Find why VdSwap is not being called**:
   - Conditional branch?
   - Early return?
   - Exception?
   - Wrong function?

### Long-term Solution

Once we find why VdSwap is not being called:
1. Fix the root cause (no workarounds!)
2. Verify VdSwap starts being called
3. Verify ring buffer gets populated
4. Verify draw commands appear
5. Verify rendering starts working

## Debug Console Cheat Sheet

```
# Quick status check
status

# Enable all tracing
profile verbose

# Enable VdSwap tracing only
trace.vdswap on

# Check PM4 buffer
pm4.dump 100
pm4.stats
pm4.opcodes

# Check system status
heap.stats
thread.list

# Break into debugger on next VdSwap
vdswap.break

# Log next 10 VdSwap calls
vdswap.log

# Clear console
clear

# Show help
help
```

## Expected Timeline

1. **Minute 1-2**: Enable tracing, check status
2. **Minute 3-5**: Analyze PM4 buffer, confirm VdSwap not called
3. **Minute 6-10**: Use CDB to break on present callback
4. **Minute 11-20**: Step through to find why VdSwap not called
5. **Minute 21-30**: Fix root cause, verify rendering works

**Total**: 30 minutes to find and fix the issue (if we're lucky!)

## Success Criteria

- ✅ VdSwap is being called
- ✅ Ring buffer has non-zero writes
- ✅ PM4 opcodes show draw commands (0x22, 0x36)
- ✅ draws > 0 in console output
- ✅ Rendering appears on screen

**When all criteria met**: Game is rendering! 🎉

