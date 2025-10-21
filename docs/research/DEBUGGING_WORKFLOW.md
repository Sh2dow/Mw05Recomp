# MW05 Debugging Workflow - Complete Guide

**Date**: 2025-10-21  
**Purpose**: Show how to debug MW05Recomp using built-in tools + external debuggers

## Overview

MW05Recomp now has **three levels of debugging**:

1. **Built-in Debug Console** - Runtime control, quick checks (press ` or F1)
2. **Environment Variables** - Backward compatibility, automated testing
3. **External Debuggers** - Deep debugging with CDB/WinDbg

## Level 1: Built-in Debug Console (Primary)

### Quick Start

```
1. Launch game: scripts\debug.cmd
2. Press ` (backtick) or F1
3. Type commands
```

### Common Commands

```
# Check current status
> status

# Enable VdSwap tracing
> trace.vdswap on

# Check PM4 buffer
> pm4.stats
> pm4.opcodes
> pm4.dump 100

# Check system status
> heap.stats
> thread.list

# Load debug profile
> profile verbose

# Clear console
> clear
```

### When to Use

- ✅ Quick status checks
- ✅ Runtime control of verbosity
- ✅ Checking PM4 buffer state
- ✅ Monitoring system resources
- ✅ Enabling/disabling tracing on the fly

### Limitations

- ❌ Can't set breakpoints
- ❌ Can't step through code
- ❌ Can't examine memory directly
- ❌ Can't inspect call stacks

## Level 2: Environment Variables (Backward Compatibility)

### Quick Start

```batch
set MW05_DEBUG_PM4=3
set MW05_PM4_TRACE=1
scripts\debug.cmd
```

### Common Variables

```batch
# Verbosity levels (0=off, 1=minimal, 2=normal, 3=verbose)
set MW05_DEBUG_GRAPHICS=3
set MW05_DEBUG_PM4=3
set MW05_DEBUG_KERNEL=2
set MW05_DEBUG_THREAD=2
set MW05_DEBUG_HEAP=1
set MW05_DEBUG_FILEIO=2

# Trace control
set MW05_HOST_TRACE_IMPORTS=1
set MW05_HOST_TRACE_HOSTOPS=1
set MW05_PM4_TRACE=1

# PM4 control
set MW05_PM4_SCAN_ALL=1
set MW05_PM4_APPLY_STATE=1
set MW05_PM4_EMIT_DRAWS=1

# File I/O control
set MW05_STREAM_BRIDGE=1
```

### When to Use

- ✅ Automated testing scripts
- ✅ CI/CD pipelines
- ✅ Reproducible debug sessions
- ✅ Batch processing

### Limitations

- ❌ Must restart app to change settings
- ❌ No runtime control
- ❌ Hard to remember variable names

## Level 3: External Debuggers (Deep Debugging)

### CDB (Command-line Debugger)

**Launch**:
```batch
scripts\debug.cmd cdb
```

**Common Commands**:
```
# Break on VdSwap
bp Mw05Recomp!VdSwap
g

# Break on present callback
bp Mw05Recomp!sub_82598A20
g

# Show call stack
k

# Step through
t

# Continue
g

# Quit
q
```

**When to Use**:
- ✅ Setting breakpoints
- ✅ Stepping through code
- ✅ Examining call stacks
- ✅ Automated debugging scripts

### WinDbg (GUI Debugger)

**Launch**:
```batch
scripts\debug.cmd windbg
```

**Common Commands**:
```
# Break on VdSwap
bp Mw05Recomp!VdSwap
g

# Break on present callback
bp Mw05Recomp!sub_82598A20
g

# Show call stack (GUI)
View -> Call Stack

# Step through (GUI)
F10 (step over)
F11 (step into)

# Continue (GUI)
F5
```

**When to Use**:
- ✅ Visual debugging
- ✅ Complex call stacks
- ✅ Memory inspection
- ✅ Register inspection

## Debugging "No Draws" Issue - Complete Workflow

### Phase 1: Quick Check (Debug Console)

```
1. Launch: scripts\debug.cmd
2. Press ` to open console
3. Check status:
   > pm4.stats
   > pm4.opcodes
   > thread.list
4. Enable tracing:
   > trace.vdswap on
   > vdswap.log
5. Wait 30 seconds
6. Check if VdSwap was called
```

**Expected**: VdSwap log messages appear  
**Actual**: NO messages = VdSwap not being called

### Phase 2: Deep Investigation (CDB)

```
1. Launch: scripts\debug.cmd cdb
2. Set breakpoint:
   bp Mw05Recomp!sub_82598A20
3. Continue:
   g
4. When breakpoint hits:
   k  (show call stack)
   t  (step through)
5. Step until VdSwap call site (line 6874)
6. Check if VdSwap is called
```

**Expected**: Execution reaches VdSwap call  
**Actual**: Execution stops before VdSwap = conditional branch or early return

### Phase 3: Root Cause Analysis (WinDbg)

```
1. Launch: scripts\debug.cmd windbg
2. Set breakpoint on present callback
3. Step through line by line
4. Find the condition that prevents VdSwap from being called
5. Examine registers/memory to understand why
6. Fix the root cause
```

### Phase 4: Verification (Debug Console)

```
1. Launch: scripts\debug.cmd
2. Press ` to open console
3. Enable tracing:
   > trace.vdswap on
4. Wait 30 seconds
5. Check:
   > pm4.stats  (should show draws > 0)
   > pm4.opcodes  (should show DRAW_INDX commands)
```

**Expected**: VdSwap is called, draws > 0, rendering works!

## Debugging Cheat Sheet

### Quick Status Check

```
# Debug Console
> status
> pm4.stats
> thread.list
> heap.stats
```

### Enable All Tracing

```
# Debug Console
> profile verbose

# OR Environment Variables
set MW05_DEBUG_GRAPHICS=3
set MW05_DEBUG_PM4=3
set MW05_DEBUG_KERNEL=3
set MW05_DEBUG_THREAD=3
set MW05_DEBUG_HEAP=3
set MW05_DEBUG_FILEIO=3
```

### Break on VdSwap

```
# CDB
bp Mw05Recomp!VdSwap
g

# WinDbg
bp Mw05Recomp!VdSwap
g
```

### Step Through Present Callback

```
# CDB
bp Mw05Recomp!sub_82598A20
g
t  (repeat until VdSwap call)

# WinDbg
bp Mw05Recomp!sub_82598A20
g
F11  (step into)
```

### Dump PM4 Buffer

```
# Debug Console
> pm4.dump 100
> pm4.opcodes
```

## Best Practices

### 1. Start with Debug Console

Always start with the built-in debug console for quick checks:
- Faster than external debuggers
- No need to restart app
- Immediate feedback

### 2. Use CDB for Breakpoints

When you need breakpoints, use CDB:
- Faster than WinDbg
- Scriptable
- Good for automated debugging

### 3. Use WinDbg for Complex Issues

When you need visual debugging, use WinDbg:
- GUI makes complex call stacks easier
- Memory/register inspection
- Better for understanding flow

### 4. Combine All Three

For complex issues, use all three:
1. Debug console for quick checks
2. CDB for breakpoints
3. WinDbg for deep analysis

## Common Debugging Scenarios

### Scenario 1: Game Crashes

```
1. Launch with CDB: scripts\debug.cmd cdb
2. Let it crash
3. CDB will break on exception
4. Show call stack: k
5. Examine registers: r
6. Find root cause
```

### Scenario 2: Performance Issue

```
1. Launch normally: scripts\debug.cmd
2. Open console: `
3. Check heap: > heap.stats
4. Check threads: > thread.list
5. Enable profiling: > profile verbose
6. Analyze logs
```

### Scenario 3: Rendering Issue

```
1. Launch normally: scripts\debug.cmd
2. Open console: `
3. Check PM4: > pm4.stats
4. Check opcodes: > pm4.opcodes
5. Enable tracing: > trace.vdswap on
6. Analyze VdSwap calls
```

### Scenario 4: File I/O Issue

```
1. Launch normally: scripts\debug.cmd
2. Open console: `
3. Enable tracing: > debug.fileio 3
4. Check logs for file operations
5. Verify streaming bridge is working
```

## Summary

**Three-Level Debugging**:
1. **Debug Console** - Quick checks, runtime control
2. **Environment Variables** - Automated testing, reproducibility
3. **External Debuggers** - Deep debugging, breakpoints

**Workflow**:
1. Start with debug console (fastest)
2. Move to CDB if you need breakpoints
3. Move to WinDbg if you need visual debugging

**Goal**: Find and fix root causes, not workarounds!

**Current Issue**: VdSwap not being called → Use CDB to find why → Fix root cause → Verify rendering works

