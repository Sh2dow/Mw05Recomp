# Callback Parameter Structure Initialization Investigation

**Date**: 2025-10-22  
**Status**: GAME STABLE - Runs 30+ seconds without crashing  
**Issue**: Callback parameter structure at `0x82A2B318` is NOT being initialized naturally

## Current Status

### ✅ What's Working
1. **Game Stability** - Runs for 30+ seconds without any crashes
2. **Infinite Recursion Bug FIXED** - `StoreBE*_Watched` functions no longer cause infinite recursion
3. **PM4 Processing** - 170,000+ packets processed successfully
4. **Graphics Callbacks** - VdCallGraphicsNotificationRoutines called 1811+ times
5. **Main Thread Active** - Alive for 32+ seconds, sleeping at `lr=0x82441E54`
6. **No NULL-CALL Floods** - Only 1 NULL-CALL error (at `lr=82441C70`)

### ⚠️ What's NOT Working
1. **No Draws** - `draws=0` in all PM4 scans (game hasn't issued any draw commands)
2. **Callback Parameter NOT Initialized** - Structure at `0x82A2B318` has `work_func=0x00000000`
3. **Missing Worker Threads** - Only 2 threads created (need 12 total)
4. **Force-Initialization Crashes** - `MW05_FORCE_INIT_CALLBACK_PARAM=1` causes message box crash

## The Callback Parameter Structure

**Address**: `0x82A2B318` (static XEX data section)  
**Size**: ~32 bytes (estimated)  
**Layout** (discovered through debugging):
```c
struct CallbackParameter {
    uint32_t field_00;           // +0x00 (0) - Unknown (0xB5901790 when initialized)
    uint32_t field_04;           // +0x04 (4) - Unknown (varies)
    uint32_t state;              // +0x08 (8) - State (0x00000001 when initialized)
    uint32_t result;             // +0x0C (12) - Result (0x00000000)
    uint32_t work_func;          // +0x10 (16) - Work function pointer (0x82441E58) - CRITICAL!
    uint32_t work_param;         // +0x14 (20) - Work function parameter (0x00000000)
    uint32_t field_18;           // +0x18 (24) - Unknown (0xB5901790 when initialized)
    uint32_t flag;               // +0x1C (28) - Flag (0 = 1 param, non-zero = 2 params)
};
```

**Current State**: All fields are `0x00000000` (uninitialized)  
**Expected State**: `work_func=0x82441E58` (main game work function)

## Investigation Findings

### 1. Address NOT Referenced in Generated Code
Searched all generated PPC files (`Mw05RecompLib/ppc/*.cpp`) for `0x82A2B318` - **NO MATCHES**.

This means the structure is NOT initialized through direct address writes. It must be initialized through:
- Base address + offset calculation (e.g., `base + 0x2B318`)
- Static C++ constructor
- Indirect pointer writes

### 2. Force-Initialization Causes Crashes
Setting `MW05_FORCE_INIT_CALLBACK_PARAM=1` causes the game to crash with a message box. This suggests:
- The structure initialization has side effects
- OR the structure must be initialized at a specific time
- OR the structure is part of a larger initialization sequence

### 3. Game Waits Indefinitely
The game runs for 30+ seconds checking the structure every second, but it NEVER gets initialized naturally. This suggests:
- The initialization is triggered by an event that's not happening
- OR the initialization function is not being called
- OR there's a missing dependency

## Comparison with Xenia

From `tools/xenia.log` analysis:
- Xenia creates 12 threads total (same as expected)
- Xenia initializes the callback parameter structure early in execution
- Xenia's worker threads start processing work immediately

**Key Difference**: In Xenia, the structure is initialized BEFORE the main game loop starts. In our implementation, the main game loop is running but the structure is never initialized.

## Possible Root Causes

### Hypothesis 1: Static Constructor Not Called
The structure might be initialized by a C++ static constructor that's not being called. This could happen if:
- The constructor is in a different compilation unit
- The constructor has dependencies that aren't met
- The constructor is being optimized out

**Investigation**: Check for static constructors in the XEX that reference this address.

### Hypothesis 2: Missing Initialization Call
There might be an initialization function that should be called early in the game startup, but it's not being called. This could happen if:
- The function is called through a vtable that's not set up
- The function is called conditionally and the condition is false
- The function is part of a callback chain that's broken

**Investigation**: Trace the execution flow from XEX entry point to find initialization calls.

### Hypothesis 3: Event-Driven Initialization
The structure might be initialized in response to a specific event (e.g., file loaded, resource ready, etc.). This could happen if:
- The event is not being triggered
- The event handler is not registered
- The event system is not working correctly

**Investigation**: Check for event registration and triggering in the game code.

## Next Steps

### Priority 1: Find the Initialization Function
1. Search for functions that write to addresses in the range `0x82A2B000-0x82A2C000`
2. Check for static constructors in the XEX
3. Trace execution flow from XEX entry point to find initialization calls

### Priority 2: Compare with Xenia Execution
1. Run Xenia with detailed logging
2. Find when the structure is initialized in Xenia
3. Compare execution flow with our implementation

### Priority 3: Investigate Alternative Approaches
1. Check if the structure can be initialized manually at a safe point
2. Investigate if there's a different structure that should be used
3. Check if the worker threads can be created without this structure

## Files Modified

### `Mw05Recomp/kernel/trace.h`
- Fixed infinite recursion in `StoreBE8_Watched` (lines 97-109)
- Fixed infinite recursion in `StoreBE32_Watched` (lines 145-153)
- Fixed infinite recursion in `StoreBE64_Watched` (lines 355-374)
- Fixed infinite recursion in `StoreBE128_Watched` (lines 463-475)
- Fixed infinite recursion in `StoreBE128_Watched_P` (lines 506-519)

### `Mw05Recomp/cpu/mw05_trace_threads.cpp`
- Added detailed logging to `sub_8262FDA8` wrapper (lines 479-527)
- Logs callback list traversal and detects corrupted function pointers

## Conclusion

The game is now STABLE and runs for 30+ seconds without crashing. The infinite recursion bug is FIXED. However, the callback parameter structure at `0x82A2B318` is NOT being initialized naturally, which prevents worker threads from being created and blocks rendering.

The next step is to find the NATURAL initialization path for this structure by:
1. Searching for initialization functions in the XEX
2. Comparing execution flow with Xenia
3. Investigating static constructors and event-driven initialization

**DO NOT** use `MW05_FORCE_INIT_CALLBACK_PARAM=1` as it causes crashes.

