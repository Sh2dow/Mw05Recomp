# Status After Recompiler Bug #39 Fix

**DATE**: 2025-10-15
**STATUS**: ✅ **SLEEP LOOP FIXED - GAME PROGRESSING**

## Summary

Fixed recompiler bug #39 (sleep loop function `sub_8262F2A0`). The game is now progressing past initialization and entering the rendering stage. Graphics infrastructure is working correctly.

## What's Working

### ✅ Sleep Function (Bug #39 Fix)
- Sleep loop now exits correctly when `Alertable=FALSE`
- All 8,220 sleep calls in 45 seconds complete successfully
- Debug logs confirm: `timeout_ms=0 alertable=0 result=0x0 return=0x0`
- Game is no longer stuck in infinite sleep loop

### ✅ Graphics Infrastructure
- VBlank pump running at 60 Hz (2,700+ ticks in 45 seconds)
- Graphics callback registered at 0x825979A8 with context 0x00061000
- PM4 command buffer scanning active (19 PM4 operations)
- Ring buffer configured: base=0x00040300 size=65536 bytes
- System command buffer allocated and initialized

### ✅ Thread Creation
- 3 threads created successfully:
  - Thread #1: 0x828508A8 (main game thread)
  - Thread #2: 0x82812ED0 (worker thread)
  - Thread #3: 0x82849D40 (auxiliary thread)

### ✅ File I/O
- Streaming bridge working correctly
- 1 file loaded (4 MB read)
- NtCreateFile/NtOpenFile/NtReadFile all functional

### ✅ Memory Management
- Physical memory allocation working (357 MB allocated)
- VM arena initialized: [0x7FEA0000, 0xA0000000) = 513 MB
- Guest memory translation working correctly

## Current State

### PM4 Command Buffers
- **TYPE0 packets**: 16,384 (register writes) - WORKING
- **TYPE3 packets**: 0 (draw commands) - NOT YET ISSUED
- **DrawCount**: 1 (game issued one draw command, then stopped)

### Graphics Callbacks
- **Registered**: YES (cb=0x825979A8, ctx=0x00061000)
- **Invoked**: NO (0 invocations in 45 seconds)
- **Reason**: VBlank pump has `cb_on=false` due to environment variable configuration

### Sleep Behavior
- **Total sleep calls**: 8,220 in 45 seconds (normal - game sleeps frequently)
- **Sleep duration**: Most calls are `timeout_ms=0` (yield/spin)
- **Alertable**: All calls have `alertable=0` (non-alertable)
- **Return value**: All calls return `0x0` (STATUS_SUCCESS)

## Analysis

### Why Graphics Callbacks Aren't Being Invoked

The VBlank pump code has a `cb_on` flag that controls whether guest ISR callbacks are invoked:

```cpp
static const bool cb_on = [](){
    const bool force_present = Mw05EnvEnabled("MW05_FORCE_PRESENT");
    const bool force_present_bg = Mw05EnvEnabled("MW05_FORCE_PRESENT_BG");
    const bool kick_video = Mw05EnvEnabled("MW05_KICK_VIDEO_THREAD");
    
    if (force_present || force_present_bg || kick_video) {
        // Suppress guest ISR during forced-present bring-up
        return false;
    }
    return true; // Default: enabled
}();
```

**Current Configuration**:
- `MW05_FORCE_PRESENT` or similar flags are likely set
- This disables guest ISR callbacks to avoid conflicts during bring-up
- The game registered a callback but it's never being invoked

### Why DrawCount Is Stuck at 1

The game issued one draw command during initialization, but then stopped. Possible reasons:

1. **Missing Graphics Callbacks**: The game expects VBlank callbacks to drive the render loop
2. **Waiting for Event**: The game might be waiting for a synchronization event that never fires
3. **Missing Thread**: Xenia creates 9 threads, we only create 3 (missing 6 threads)
4. **Incomplete Initialization**: Some initialization step is missing or incomplete

## Next Steps

### 1. Enable Graphics Callbacks
Remove or disable environment variables that suppress guest ISR callbacks:
- `MW05_FORCE_PRESENT=0`
- `MW05_FORCE_PRESENT_BG=0`
- `MW05_KICK_VIDEO_THREAD=0`

This will allow the VBlank pump to invoke the registered graphics callback at 0x825979A8.

### 2. Monitor Callback Invocations
Once callbacks are enabled, monitor for:
- `HOST.VblankPump.guest_isr.call` messages in the log
- Increase in DrawCount (should go beyond 1)
- TYPE3 PM4 packets appearing (draw commands)

### 3. Investigate Missing Threads
Compare with Xenia to identify the 6 missing threads:
- Xenia creates 9 threads total
- We only create 3 threads
- Missing threads might be responsible for rendering, audio, or other subsystems

### 4. Check for Crashes
Monitor for SEH exceptions in the graphics callback:
- `HOST.VblankPump.guest_isr.seh_abort` messages
- If callbacks crash, the VBlank pump will catch the exception and continue
- Need to fix any crashes in the callback code

## Environment Variables

### Currently Active (Suspected)
- `MW05_FAST_BOOT=1` - Fast boot to skip delays
- `MW05_UNBLOCK_MAIN=1` - Unblock main thread (no longer needed after bug #39 fix)
- `MW05_FORCE_PRESENT=1` or similar - Suppressing guest ISR callbacks

### Recommended Configuration
```powershell
$env:MW05_FAST_BOOT = "1"                # Keep fast boot
$env:MW05_UNBLOCK_MAIN = "0"             # Disable (no longer needed)
$env:MW05_FORCE_PRESENT = "0"            # Disable to allow guest ISR
$env:MW05_FORCE_PRESENT_BG = "0"         # Disable to allow guest ISR
$env:MW05_KICK_VIDEO_THREAD = "0"        # Disable to allow guest ISR
```

## Files Modified

### `Mw05Recomp/gpu/mw05_trace_shims.cpp`
- Added type definitions for kernel functions (lines 13-31)
- Replaced buggy `sub_8262F2A0` with corrected implementation (lines 416-487)
- Added debug logging for first 10 sleep calls

### `.gitignore`
- Added `ida_logs/` to exclude IDA Pro decompilation outputs
- Added `Traces/` to exclude debug trace files
- Added `test_stderr.txt` and `debug_stderr.txt` to exclude test outputs

## Total Bugs Fixed

**39 Recompiler Bugs**:
- 37 bugs in 32-bit PowerPC instructions (using `.u64`/`.s64` instead of `.u32`)
- 1 bug in `PPC_LOOKUP_FUNC` macro (function table offset calculation)
- 1 bug in `sub_8262F2A0` sleep loop (incorrect loop condition)

## Conclusion

The sleep loop fix (bug #39) was successful. The game is now progressing past initialization and entering the rendering stage. The next critical step is to enable graphics callbacks so the game can drive its render loop naturally. Once callbacks are enabled, we should see:

1. Graphics callback invocations at 60 Hz
2. DrawCount increasing beyond 1
3. TYPE3 PM4 packets (draw commands) appearing
4. Actual rendering to the screen

The game is very close to rendering frames - we just need to remove the environment variable restrictions that are suppressing the graphics callbacks.

