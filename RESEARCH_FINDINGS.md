# Research Findings: Event 0x400007E0 and Missing Threads

**Date**: 2025-10-14  
**Status**: ROOT CAUSE IDENTIFIED

## Critical Findings

### 1. Wrong Context Address for Render Thread

**Xenia (CORRECT)**:
```
ExCreateThread: entry=0x825AA970 ctx=0x40009D2C flags=0x04000080
```

**Our Implementation (WRONG)**:
```
ExCreateThread: entry=0x825AA970 ctx=0x7FEA17B0 flags=0x00000000
```

**Impact**: The render thread expects a specific context structure at `0x40009D2C`, but we're passing a different address!

### 2. Event Address Calculation

From disassembly of `sub_825AA970` (render thread entry):
```asm
0x825AA984: addi r28, r26, 0x20    # r28 = ctx + 0x20
0x825AAA1C: mr   r3, r28            # r3 = event object
0x825AAA20: bl   KeWaitForSingleObject
```

**Event address**: `ctx + 0x20 = 0x40009D2C + 0x20 = 0x40009D4C`

The render thread waits on event at `0x40009D4C`, NOT `0x400007E0`!

### 3. Who Signals the Event?

From Xenia log:
```
i> 01000010 [MW05] KeSetEvent ea=0x40009D4C incr=1 wait=0 signal_state=0
```

**Thread 01000010** (GPU Commands HOST thread) signals the event!

This happens repeatedly in a loop:
- GPU Commands thread calls `KeSetEvent(0x40009D4C)`
- Render thread wakes up from `KeWaitForSingleObject(0x40009D4C)`
- Render thread processes frame and calls present
- Render thread goes back to waiting on the event
- Cycle repeats

### 4. Missing Threads

**Xenia creates 13 threads total**:
1. GPU Commands (tid=1, **HOST THREAD**, entry=0x00000000)
2. GPU Frame limiter (tid=2, **HOST THREAD**, entry=0x00000000)
3. XMA Decoder (tid=3, **HOST THREAD**, entry=0x00000000)
4. Audio Worker (tid=4, **HOST THREAD**, entry=0x00000000)
5. Kernel Dispatch (tid=5, **HOST THREAD**, entry=0x00000000)
6. Main XThread (tid=6, entry=0x8262E9A8, SUSPENDED)
7. XThread489C (tid=7, entry=0x828508A8, SUSPENDED)
8. XThread2EBC (tid=8, entry=0x82812ED0, SUSPENDED)
9. XThread1984 (tid=9, entry=0x828508A8, SUSPENDED)
10. XThread0B10 (tid=A, entry=0x828508A8, SUSPENDED)
11. XThread330C (tid=B, entry=0x828508A8, SUSPENDED)
12. XThread64CC (tid=C, entry=0x828508A8, SUSPENDED)
13. **Render Thread** (tid=D, entry=0x825AA970, ctx=0x40009D2C, flags=0x04000080)

**We only create 3 threads**:
1. Thread #1 (entry=0x828508A8, SUSPENDED)
2. Thread #2 (entry=0x82812ED0, SUSPENDED)
3. Thread #3 (entry=0x825AA970, RUNNING) - force-created with WRONG context!

**Missing**: Threads 6-12 (Main XThread + 6 suspended worker threads)

### 5. GPU Commands Thread Implementation

**Xenia's GPU Commands thread**:
- Runs continuously in a loop
- Calls `KeSetEvent(0x40009D4C)` to wake up render thread
- Drives the rendering pipeline

**Our GPU Commands thread** (in `Mw05Recomp/kernel/system_threads.cpp`):
```cpp
static void GpuCommandsThreadEntry()
{
    while (g_systemThreadsRunning.load(std::memory_order_acquire))
    {
        // Sleep for 16ms (60 FPS)
        std::this_thread::sleep_for(std::chrono::milliseconds(16));
    }
}
```

**Problem**: Just sleeps, doesn't signal any events!

## Root Cause Summary

The render thread is NOT stuck waiting on `0x400007E0`. It's waiting on `0x40009D4C` (ctx+0x20).

**Three critical bugs**:

1. **Wrong context address** - Using `0x7FEA17B0` instead of `0x40009D2C`
2. **Event not initialized** - Event at `ctx+0x20` is not initialized as a valid KEVENT
3. **GPU Commands thread not working** - Doesn't signal the render thread's event

## Solution

### Fix 1: Use Correct Context Address

Change `run_with_debug.ps1`:
```powershell
$env:MW05_RENDER_THREAD_CTX = "0x40009D2C"  # Correct context from Xenia
```

### Fix 2: Initialize Event at ctx+0x20

In `Mw05ForceCreateRenderThreadIfRequested()`, add:
```cpp
// Initialize the event at ctx+0x20
uint32_t event_ea = ctx + 0x20;  // 0x40009D2C + 0x20 = 0x40009D4C
if (auto* evt = reinterpret_cast<XKEVENT*>(g_memory.Translate(event_ea))) {
    evt->Header.Type = 0;  // Auto-reset event
    evt->Header.SignalState = be<int32_t>(0);  // Not signaled
    evt->Header.WaitListFlink = be<uint32_t>(event_ea + offsetof(XKEVENT, Header.WaitListFlink));
    evt->Header.WaitListBlink = be<uint32_t>(event_ea + offsetof(XKEVENT, Header.WaitListBlink));
    fprintf(stderr, "[RENDER-THREAD] Initialized event at 0x%08X (ctx+0x20)\n", event_ea);
}
```

### Fix 3: Make GPU Commands Thread Signal the Event

In `Mw05Recomp/kernel/system_threads.cpp`, change `GpuCommandsThreadEntry()`:
```cpp
static void GpuCommandsThreadEntry()
{
    KernelTraceHostOp("HOST.SystemThread.GPUCommands.start");
    fprintf(stderr, "[SYSTEM-THREAD] GPU Commands thread started\n");
    
    // Get the render thread event address from environment
    const char* ctx_str = std::getenv("MW05_RENDER_THREAD_CTX");
    uint32_t ctx = ctx_str ? (uint32_t)std::strtoul(ctx_str, nullptr, 0) : 0x40009D2C;
    uint32_t event_ea = ctx + 0x20;  // Event is at ctx+0x20
    
    while (g_systemThreadsRunning.load(std::memory_order_acquire))
    {
        // Signal the render thread event to wake it up
        if (auto* evt = reinterpret_cast<XKEVENT*>(g_memory.Translate(event_ea))) {
            KeSetEvent(evt, 1, false);
        }
        
        // Sleep for 16ms (60 FPS)
        std::this_thread::sleep_for(std::chrono::milliseconds(16));
    }
    
    KernelTraceHostOp("HOST.SystemThread.GPUCommands.exit");
}
```

## Expected Result

After these fixes:
1. Render thread will be created with correct context (`0x40009D2C`)
2. Event at `0x40009D4C` will be properly initialized
3. GPU Commands thread will signal the event every 16ms
4. Render thread will wake up, process frame, call present, and go back to sleep
5. **Draw commands should appear!**

## Additional Notes

### Event 0x400007E0 vs 0x40009D4C

The event `0x400007E0` mentioned in the environment variables is NOT the render thread event. It might be:
- A different event used by other threads
- A VD interrupt event for graphics callbacks
- Not relevant to the render thread at all

The render thread specifically waits on `ctx+0x20`, which is `0x40009D4C` when ctx=`0x40009D2C`.

### Thread Creation Order

Xenia creates threads in this order:
1. Host threads (GPU Commands, XMA Decoder, etc.) - created at startup
2. Main XThread (tid=6) - created by game initialization
3. Worker threads (tid=7-12) - created by Main XThread
4. Render thread (tid=13) - created by one of the worker threads

We're force-creating the render thread too early, before the worker threads exist. This might cause issues with thread synchronization.

### Flags 0x04000080

The render thread is created with flags `0x04000080`:
- `0x00000080` = CREATE_SUSPENDED (bit 7)
- `0x04000000` = Unknown flag (bit 26)

But Xenia's log shows the thread is NOT suspended (it starts running immediately). This suggests the flags might be processed differently, or the thread is resumed immediately after creation.

Our implementation uses `flags=0x00000000` (not suspended), which might be correct if we want the thread to start immediately.

