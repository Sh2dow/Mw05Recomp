# Rendering Progress

## Current Status
- ✅ **Rendering function IS being called** - `sub_82598A20` called 7 times
- ✅ **VdSwap IS being invoked** - GPU command buffer submission working
- ✅ **PM4 ring buffer working** - Millions of packets processed
- ⚠️ **Rendering stopped after 7 calls** - Function pointer gate issue
- ⚠️ **NO draw commands** (draws=0) - Game stuck in initialization

## Breakthrough: Rendering Function Called!

### Evidence
- Function `sub_82598A20` called 7 times during test run
- All 7 calls resulted in `VdSwap` being invoked
- Call pattern: `[PRESENT-CB] sub_82598A20 called! count=X r3=0009B200 r4=00040360 lr=82597AB4`
- VdSwap parameters: r3=0x140410 (command buffer), r4=0x40370 (graphics context), r5=0x8 (flags)

### Why It Stopped
**Function Pointer Gate** at offset +0x3CEC:
- Rendering function called through function pointer at `r31 + 0x3CEC` (offset 15596)
- `r31 = 0x00040360` (graphics context)
- Function pointer address: `0x00040360 + 0x3CEC = 0x0004404C`
- After 7 calls, something clears this pointer to NULL
- When NULL, rendering function is skipped

## PM4 Analysis

### Current State
- PM4 buffer being scanned (consuming 65,536 to 120,824 bytes per frame)
- Millions of packets processed (114,616 bytes/frame average)
- **draws=0** - NO draw commands detected
- Only opcodes 0x00 (NOP) and 0x4F being processed

### Expected Draw Opcodes (NOT appearing)
- `0x22` (PM4_DRAW_INDX) - Standard draw indexed
- `0x36` (PM4_DRAW_INDX_2) - Draw indexed variant
- `0x04` (Micro-IB commands) - MW05's custom draw system

### What This Means
- Game is setting up GPU state (register writes, NOP commands)
- But hasn't started issuing actual draw commands yet
- This is NORMAL for initialization phase
- Game needs to complete resource loading before rendering

## VdSwap Investigation

### Ring Buffer Status
- Ring buffer initialized correctly (base=0x00040300, size=64KB)
- System command buffer initialized (base=0x00F00000, size=64KB)
- Write cursor validation working
- PM4_ScanLinear processing command buffers

### VdSwap Call Pattern
```
Call 1: System command buffer pointer NULL
Call 2-7: System command buffer pointer valid (0x140410)
After call: System command buffer pointer cleared back to NULL
```

This suggests the function is consuming the command buffer and clearing it after processing.

## File I/O Status
- ✅ **269+ file I/O operations** detected in trace log
- ✅ **Loading GLOBALMEMORYFILE.BIN** (6.3 MB file)
- ✅ **StreamBridge successfully triggered** and loading resources
- Game can load resources, progressing through initialization

## Next Actions
1. **Investigate function pointer gate** - Find what clears pointer at +0x3CEC, determine if intentional or bug
2. **Extended runtime testing** - Run game for 30+ minutes to see if rendering eventually starts
3. **Simulate user input** - Try controller/keyboard input to see if game progresses
4. **Compare with Xenia** - Check what triggers first draw in Xenia's execution
5. **Monitor PM4 opcodes** - Watch for appearance of 0x22/0x36 draw commands

