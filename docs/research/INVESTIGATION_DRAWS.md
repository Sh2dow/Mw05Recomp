# Investigation: Why Game Isn't Issuing Draw Commands

**Date**: 2025-10-14  
**Status**: Render thread created successfully, but still no draws

## Summary

I've successfully identified and partially resolved the issue of why the game isn't issuing draw commands:

### What Was Fixed

1. **Environment Variable Bug** - Fixed `run_with_debug.ps1` to properly inherit environment variables
2. **Present Callback** - Now working correctly after environment variable fix
3. **Render Thread Creation** - Successfully created Thread #3 (entry=0x825AA970) at tick 150

### Current Status

✅ Render thread created successfully  
✅ Thread #3 is RUNNING (not suspended)  
✅ PM4 scanning is happening  
✅ Present function is being called  
❌ **Still no draw commands** - PM4 scans show `draws=0`

## Investigation Findings

### 1. Xenia Analysis

From the Xenia log (`tools/xenia.log`):
- First draw appears at line 35748
- Thread `01000010` ("GPU Commands") issues the draws
- Before the first draw, there are lots of `KeDelayExecutionThread` and `NtWaitForSingleObjectEx` calls
- Event `0x400007E0` is being signaled via `KeSetEvent`
- The render thread waits on this event before issuing draws

### 2. Our Implementation

**Threads Created**:
- Thread #1: entry=0x828508A8, ctx=0x7FEA17B0, SUSPENDED
- Thread #2: entry=0x82812ED0, ctx=0x002B8E10, SUSPENDED  
- Thread #3: entry=0x825AA970, ctx=0x7FEA17B0, **RUNNING** (render thread, force-created)

**System Threads** (host threads, not guest):
- GPU Commands thread (just sleeps, doesn't process commands)
- GPU Frame limiter thread
- XMA Decoder thread
- Audio Worker thread
- Kernel Dispatch thread

### 3. The Problem

The render thread (Thread #3) is running, but it's not issuing draw commands. Possible reasons:

1. **Waiting for an event** - The thread might be waiting on event `0x400007E0` which isn't being signaled
2. **Missing initialization** - Some graphics state might not be initialized
3. **Stuck in a loop** - The thread might be stuck in a wait loop or checking a flag that's never set
4. **Missing resources** - The thread might be waiting for resources to load

### 4. Key Environment Variables

From `run_with_debug.ps1`:
```powershell
$env:MW05_FORCE_RENDER_THREAD = "1"                # ✅ WORKING - Thread created
$env:MW05_FORCE_RENDER_THREAD_DELAY_TICKS = "150" # ✅ WORKING - Thread created at tick 150
$env:MW05_RENDER_THREAD_ENTRY = "0x825AA970"      # ✅ WORKING - Correct entry point
$env:MW05_RENDER_THREAD_CTX = "0x7FEA17B0"        # ✅ WORKING - Correct context
$env:MW05_HOST_ISR_SIGNAL_VD_EVENT = "1"          # ❓ UNKNOWN - Need to verify if event is being signaled
$env:MW05_PULSE_VD_EVENT_ON_SLEEP = "1"           # ❓ UNKNOWN - Need to verify if event is being pulsed
$env:MW05_FORCE_PRESENT_FLAG = "1"                # ✅ WORKING - Flag set at 0x00012A81 and 0x00012A80
```

## Next Steps

### Immediate Actions

1. **Check if event 0x400007E0 is being signaled**
   - Search stderr for `KeSetEvent` or `NtSetEvent` calls
   - Verify that `MW05_HOST_ISR_SIGNAL_VD_EVENT` is actually signaling the event
   - Compare with Xenia's event signaling pattern

2. **Trace the render thread execution**
   - Add logging to see what the render thread is doing
   - Check if it's stuck in a wait loop
   - Verify that it's reaching the draw command submission code

3. **Check for missing kernel functions**
   - The render thread might be calling kernel functions that aren't implemented
   - Look for STUB messages or NOT IMPLEMENTED messages in stderr

4. **Verify graphics context initialization**
   - The render thread expects certain graphics state to be initialized
   - Check if all required graphics context members are set correctly

### Investigation Commands

```powershell
# Check if KeSetEvent is being called
Get-Content out/build/x64-Clang-Debug/Mw05Recomp/debug_stderr.txt | Select-String 'KeSetEvent|NtSetEvent' | Select-Object -First 20

# Check what Thread #3 is doing
Get-Content out/build/x64-Clang-Debug/Mw05Recomp/debug_stderr.txt | Select-String 'Thread #3|00007554' | Select-Object -First 50

# Check for wait calls
Get-Content out/build/x64-Clang-Debug/Mw05Recomp/debug_stderr.txt | Select-String 'NtWaitForSingleObjectEx|KeWaitForSingleObject|400007E0' | Select-Object -First 20

# Check for STUB or NOT IMPLEMENTED messages
Get-Content out/build/x64-Clang-Debug/Mw05Recomp/debug_stderr.txt | Select-String 'STUB|NOT IMPLEMENTED' | Select-Object -Last 50
```

### Code Locations

- **Render thread creation**: `Mw05Recomp/kernel/imports.cpp` line 6507-6644
- **VBlank pump**: `Mw05Recomp/kernel/imports.cpp` line 1672+
- **Event signaling**: Search for `MW05_HOST_ISR_SIGNAL_VD_EVENT` in `imports.cpp`
- **Graphics callback**: `Mw05Recomp/kernel/imports.cpp` line 7100+

## Conclusion

The render thread is now created and running, which is significant progress! However, it's not issuing draw commands yet. The next step is to investigate why the thread isn't progressing to the draw command submission code. This likely involves:

1. Signaling the VD interrupt event (`0x400007E0`) to wake up the render thread
2. Ensuring all required graphics state is initialized
3. Implementing any missing kernel functions the render thread needs

The fact that the thread was created successfully suggests we're very close to getting draws working!

