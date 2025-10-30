# MW05 Initialization Stuck - Root Cause and Fix

**Date**: 2025-10-29  
**Status**: ROOT CAUSE IDENTIFIED - FIX NEEDED

## Problem Statement
Game is stuck after VdSetGraphicsInterruptCallback. VBlank callbacks firing, main loop running, GPU ring buffer initialized, but **NO draw commands** and **NO file I/O**. Game has not progressed to rendering stage.

## Investigation Summary

### What Works ✅
1. **VdSetGraphicsInterruptCallback** registered (cb=0x825979A8, ctx=0x40007180)
2. **VBlank callbacks** firing regularly (source=0 and source=1)
3. **Main loop flag** being set correctly
4. **GPU ring buffer** initialized (base=0x001002E0, size=65536 bytes)
5. **GPU Commands event** being signaled 60 times/second (event 0x40009D4C)
6. **Main thread** alive and running (heartbeat every second)

### What Doesn't Work ❌
1. **NO draw commands** - PM4 scanner shows draws=0
2. **NO file I/O** - Game not loading any assets (GLOBAL/, CARS/, etc.)
3. **Game stuck in initialization** - Never progresses to rendering stage

## Xenia Behavior (WORKING)

In Xenia emulator, the game works correctly:

1. **VdSetGraphicsInterruptCallback** called (line 35556 in xenia.log)
2. **VBlank callbacks** start (source=0 and source=1)
3. **193 lines later** - First draw command appears!
4. **Thread 01000010** "GPU Commands" issues draw commands:
   ```
   i> 01000010 [MW05] Draw opcode=PM4_DRAW_INDX_2 prim=1 indices=1 indexed=0
   ```

### Key Xenia Thread: "GPU Commands" (01000010)
```
i> 00000AA4 [MW05-THREAD] Thread created: tid=1 entry=0x00000000 name='GPU Commands (01000010)'
K> 01000010 XThread::Execute thid 1 (handle=01000010, 'GPU Commands (01000010)')
i> 01000010 [MW05] RB base=0x0A0F8000 size=0x00008000 rptr=0x00000016 wptr=0x00000019
i> 01000010 [MW05] Draw opcode=PM4_DRAW_INDX_2 prim=1 indices=1 indexed=0
```

This thread:
- Reads PM4 ring buffer (rptr/wptr)
- Processes PM4 commands
- Issues draw commands
- Drives the rendering pipeline

## Our Implementation (BROKEN)

### GPU Commands Thread is a STUB!

**File**: `Mw05Recomp/kernel/system_threads.cpp`

```cpp
static void GpuCommandsThreadEntry()
{
    KernelTraceHostOp("HOST.SystemThread.GPUCommands.start");
    fprintf(stderr, "[SYSTEM-THREAD] GPU Commands thread started\n");
    
    uint32_t event_ea = 0x40009D4C;  // Event address
    
    while (g_systemThreadsRunning.load(std::memory_order_acquire)) {
        // Signal the event
        if (auto* evt = reinterpret_cast<KEVENT*>(g_memory.Translate(event_ea))) {
            KeSetEvent(evt, 1, false);
            signal_count++;
        }
        
        // Sleep for 16ms (60 FPS)
        std::this_thread::sleep_for(std::chrono::milliseconds(16));
    }
}
```

**This is WRONG!** The thread:
- ✅ Signals an event every 16ms
- ❌ Does NOT read the PM4 ring buffer
- ❌ Does NOT process PM4 commands
- ❌ Does NOT issue draw commands

## ROOT CAUSE

**The GPU Commands thread is a placeholder stub that doesn't actually process the PM4 ring buffer!**

In Xenia, this thread is the **core of the rendering pipeline** - it reads PM4 commands from the ring buffer and executes them. Without this, the game can write PM4 commands to the ring buffer all day long, but nothing will ever process them!

## The Fix

### Step 1: Implement PM4 Ring Buffer Processing

The GPU Commands thread needs to:

1. **Read ring buffer pointers**:
   - Read pointer (rptr) - where we've processed up to
   - Write pointer (wptr) - where the game has written up to
   - Writeback address (wb_ea) - where to write updated rptr

2. **Process PM4 commands**:
   - Read commands between rptr and wptr
   - Parse PM4 packets (TYPE0, TYPE3, etc.)
   - Execute draw commands (DRAW_INDX, DRAW_INDX_2, Micro-IB)
   - Update GPU state (registers, textures, shaders)

3. **Update read pointer**:
   - Write updated rptr back to writeback address
   - Signal completion event

### Step 2: Use Existing PM4 Parser

We already have PM4 parsing code in `Mw05Recomp/gpu/pm4_parser.cpp`. The GPU Commands thread should call these functions to process the ring buffer.

### Step 3: Ring Buffer State

The ring buffer state is stored in memory:
- **Base address**: Set by `VdInitializeRingBuffer` (we saw base=0x001002E0)
- **Size**: 65536 bytes (size_log2=16)
- **Read pointer writeback**: Set by `VdEnableRingBufferRPtrWriteBack`
- **Write pointer**: Updated by game when it writes PM4 commands

## Implementation Plan

1. **Find ring buffer state in memory**:
   - Search for where VdInitializeRingBuffer stores the base/size
   - Find the rptr/wptr addresses
   - Find the writeback address

2. **Modify GpuCommandsThreadEntry**:
   - Read rptr and wptr from memory
   - If rptr != wptr, process commands
   - Call PM4 parser to process commands
   - Update rptr after processing
   - Write rptr to writeback address

3. **Test**:
   - Run game and check for PM4 commands being processed
   - Verify draws > 0
   - Verify game progresses to file loading

## Expected Outcome

After implementing PM4 ring buffer processing in the GPU Commands thread:
- ✅ PM4 commands will be processed
- ✅ Draw commands will be issued
- ✅ Game will progress past initialization
- ✅ File loading will start
- ✅ Rendering will begin

## Related Files

- `Mw05Recomp/kernel/system_threads.cpp` - GPU Commands thread (NEEDS FIX)
- `Mw05Recomp/gpu/pm4_parser.cpp` - PM4 command parser (ALREADY EXISTS)
- `Mw05Recomp/kernel/imports.cpp` - VdInitializeRingBuffer, VdEnableRingBufferRPtrWriteBack
- `tools/xenia.log` - Reference implementation behavior

## Next Steps

1. Implement PM4 ring buffer processing in GPU Commands thread
2. Test with 30-second run
3. Verify draws > 0 and game progresses
4. Document results

## References

- Xenia emulator: GPU Commands thread implementation
- Xbox 360 PM4 command reference
- MW05 ring buffer initialization in xenia.log (lines 35556-35754)

