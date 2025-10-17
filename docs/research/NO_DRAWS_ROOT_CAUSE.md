# NO DRAWS ROOT CAUSE ANALYSIS

**Date**: 2025-10-17  
**Status**: 🔍 **INVESTIGATING** - Ring buffer is cleared but no PM4 commands written  
**Priority**: 🔴 **CRITICAL** - Blocking all rendering progress

## Executive Summary

The game is running stably without crashes, but **NO DRAW COMMANDS** are being issued. Investigation reveals:

✅ **Ring buffer is initialized** - Base: 0x000202E0, Size: 65536 bytes  
✅ **Ring buffer is being scanned** - 4096 packets scanned per frame  
✅ **Graphics callbacks are working** - VBlank ISR invokes callback at 0x825979A8  
✅ **Present function is being called** - sub_82598A20 executes every frame  
❌ **Ring buffer is EMPTY** - Only 16 non-zero DWORDs out of 16384 (0.098%)  
❌ **Ring buffer was CLEARED** - 16380 DWORDs changed from DEADBEEF to 0x00000000 (99.98%)  

## Key Finding

The game has **CLEARED THE RING BUFFER** but hasn't written any PM4 commands to it yet.

### Ring Buffer Memory Stats
```
PM4.ScanAll.memstats nonzero_dwords=16 total_dwords=16384
PM4.RingScratch.differs dwords_changed=16380 of 16384
```

**Analysis**:
- Ring buffer was initialized with scratch pattern `0xDEADBEEF`
- Game overwrote 99.98% of the buffer with `0x00000000`
- Only 16 DWORDs (64 bytes) remain non-zero
- This suggests the game is **initializing/clearing** the ring buffer but not **using** it yet

## What's Working

### 1. Ring Buffer Initialization ✅
```
[HOST] import=HOST.VdInitializeRingBuffer base=000202E0 len_log2=16
[HOST] import=HOST.PM4.SetRingBuffer base=000202E0 size_log2=16 size=00010000
[HOST] import=HOST.PM4.RingScratch.armed base=000202E0 size=65536 pattern=DEADBEEF
```

The ring buffer is properly initialized at guest address 0x000202E0 with 65536 bytes.

### 2. Ring Buffer Scanning ✅
```
[HOST] import=HOST.PM4.ScanAll.begin base=000202E0 size=65536 (force)
[HOST] import=HOST.PM4.ScanAll.end scanned=4096 draws=0 (force)
```

The ring buffer is being scanned every frame, processing 4096 packets (65536 bytes / 16 bytes per packet).

### 3. Graphics Callbacks ✅
```
[HOST] import=HOST.VblankPump.guest_isr.call ticks=2 cb=825979A8 ctx=00040360 count=0
[HOST] import=sub_82598A20.PRESENT enter lr=82597AB4 r3=000991C0 r4=00040360
```

The VBlank ISR is calling the graphics callback at 0x825979A8, which calls the present function at 0x82598A20.

### 4. System Command Buffer ✅
```
[HOST] import=HOST.VdGetSystemCommandBuffer.res buf=00F00000 val=00000000
```

The system command buffer at 0x00F00000 is initialized and accessible.

## What's NOT Working

### 1. No PM4 Commands in Ring Buffer ❌

The ring buffer contains:
- **16 non-zero DWORDs** (0.098% of buffer)
- **16380 zero DWORDs** (99.98% of buffer)

This means the game has **cleared** the ring buffer but hasn't **written** any PM4 commands to it.

### 2. No PM4 Commands in System Buffer ❌

The system command buffer at 0x00F00000 is also empty (all zeros):
```
[HOST] import=HOST.PM4.SysBufDump 00F00000: 00000000 (first)
[HOST] import=HOST.PM4.SysBufDump 00F00004: 00000000
[HOST] import=HOST.PM4.SysBufDump 00F00008: 00000000
...
```

### 3. No File I/O ❌

The game has not called any file I/O functions:
- No `NtCreateFile` calls
- No `NtOpenFile` calls
- No `NtReadFile` calls

This suggests the game is **waiting for something** before it starts loading resources and rendering.

## Comparison with Xenia

### Xenia (Working)
From the AGENTS.md file:
```
Line 1280-317729: Game sleeps 149,148 times (this is NORMAL!)
Line 35788+: VD notify callback invoked, NEW THREAD created
Line 317731: First draw command issued!
```

**Key insight**: In Xenia, the VD notify callback triggers **NEW THREAD CREATION** for rendering, and that new thread issues draw commands.

### Our Implementation (Current)
```
VBlank ISR calls graphics callback at 0x825979A8
Graphics callback calls present function at 0x82598A20
Present function returns without issuing draw commands
```

**Missing**: The game is not creating the render threads that would write PM4 commands to the ring buffer!

## Root Cause Hypothesis

The game is **waiting for a condition** before it creates render threads and starts issuing draw commands. Possible conditions:

1. **Missing kernel function** - A required kernel function is not implemented, blocking thread creation
2. **Missing initialization** - Some initialization step is missing, preventing the game from progressing
3. **Resource loading** - The game is waiting for resources to load (but file I/O is not happening)
4. **Synchronization primitive** - The game is waiting on a semaphore/event that's never signaled
5. **Graphics state** - The game is waiting for some graphics state to be initialized

## Investigation Steps

### 1. Check Thread Creation
Compare the number of threads created in Xenia vs our implementation:
- Xenia: 9 threads created
- Ours: 3 threads created
- **Missing**: 6 threads (including render threads)

**Action**: Find where Xenia creates the additional threads and why we're not creating them.

### 2. Check Graphics Callback Implementation
The graphics callback at 0x825979A8 should be creating render threads. Let me check if it's doing that:

**Action**: Add logging to the graphics callback to see what it's doing.

### 3. Check for Missing Kernel Functions
The game might be calling kernel functions that are not implemented, causing it to block or fail silently.

**Action**: Enable full kernel function tracing and look for STUB messages.

### 4. Check for Synchronization Issues
The game might be waiting on a semaphore/event that's never signaled.

**Action**: Check KeWaitForSingleObject calls and see if any are blocking indefinitely.

### 5. Compare Execution Flow with Xenia
Compare the execution flow step-by-step with Xenia to find where we diverge.

**Action**: Use the Xenia log to trace the exact sequence of events leading to the first draw command.

## CRITICAL FINDING: Present Callback Calls VdSwap!

**UPDATE 2025-10-17**: Decompiled the present callback (sub_82598A20) and found that it **CALLS VdSwap**!

```c
// From sub_82598A20 decompilation:
((void (__fastcall *)(int, _DWORD *, int, char *, int, unsigned int *, int *, int *))VdSwap[0])(
    v16 + 4,
    a2 + 4,
    *(_DWORD *)(a1 + 10384) + 8,
    v58,
    v54,
    &v49,
    &v52,
    &v53);
```

This means:
1. VBlank ISR calls graphics callback (sub_825979A8)
2. Graphics callback calls present callback (sub_82598A20)
3. **Present callback calls VdSwap**
4. VdSwap should process PM4 commands and present the frame

**But VdSwap is not finding any PM4 commands!**

The question is: **Why is the ring buffer empty when VdSwap is called?**

Possible answers:
1. The game writes PM4 commands AFTER calling VdSwap (wrong order)
2. The game writes PM4 commands to a different buffer
3. The game is waiting for something before writing PM4 commands
4. Our VdSwap implementation is not processing the ring buffer correctly

## Next Steps

### Immediate Priority
1. **Analyze VdSwap implementation** to see if it's processing the ring buffer correctly
2. **Check if game writes PM4 commands AFTER VdSwap** (wrong order)
3. **Compare VdSwap parameters** with Xenia to see if we're getting the right values
4. **Add logging to VdSwap** to see what parameters it receives

### After Finding Root Cause
1. **Fix VdSwap implementation** if it's not processing the ring buffer correctly
2. **Fix PM4 command buffer scanning** if we're looking in the wrong place
3. **Verify PM4 commands are written** to ring buffer
4. **Verify draw commands appear** in PM4 scans

## Technical Details

### Ring Buffer Layout
```
Base: 0x000202E0 (guest address)
Size: 0x00010000 (65536 bytes = 64 KiB)
Write-back: 0x000402E0 (GPU writes read pointer here)
GPU ID: 0x000402E8 (GPU identifier address)
```

### System Command Buffer Layout
```
Base: 0x00F00000 (guest address)
Size: 0x00010000 (65536 bytes = 64 KiB)
```

### PM4 Packet Types
- **TYPE0**: Register write (opcode 0x00)
- **TYPE1**: Reserved
- **TYPE2**: Reserved
- **TYPE3**: Command packet (draw, clear, etc.)

### Current PM4 Statistics
```
TYPE0 packets: 16000+ (all from scanning zeros)
TYPE1 packets: 0
TYPE2 packets: 0
TYPE3 packets: 0
Draw commands: 0
```

## References

- [AGENTS.md](../../AGENTS.md) - Current status and debugging information
- [FINAL_STATUS_GAME_RUNNING.md](FINAL_STATUS_GAME_RUNNING.md) - Previous milestone
- [tools/xenia.log](../../tools/xenia.log) - Reference log from working Xenia emulator
- [Mw05Recomp/gpu/pm4_parser.cpp](../../Mw05Recomp/gpu/pm4_parser.cpp) - PM4 parsing implementation
- [Mw05Recomp/kernel/imports.cpp](../../Mw05Recomp/kernel/imports.cpp) - Kernel function implementations

## Conclusion

The game is **stable and running**, but **not rendering** because:
1. Ring buffer is cleared but empty (no PM4 commands)
2. System command buffer is empty (no PM4 commands)
3. Render threads are not being created
4. File I/O is not happening

The root cause is likely a **missing initialization step** or **missing kernel function** that's preventing the game from creating render threads and starting the rendering pipeline.

**Next action**: Deep investigation of thread creation and graphics callback to find what's blocking progress.

