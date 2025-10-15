# MW05 Recompilation - Deep Investigation Summary

## Executive Summary

After extensive investigation using custom analysis tools and deep comparison with Xenia emulator logs, we've identified the root causes of why the game is stuck in initialization and not progressing to rendering.

**Key Finding**: The sleep loop is **NORMAL BEHAVIOR**. In Xenia, the game sleeps 149,148 times before issuing the first draw command. Our implementation is stuck because critical initialization threads are never created.

## Current State

### ✅ What's Working

1. **Import Table Processing** - 388/719 imports (54%) successfully patched
2. **VBlank Pump** - Running before guest thread, ticks happening
3. **Graphics Initialization** - VdInitializeEngines called, callbacks registered
4. **Graphics Callbacks** - ~2,000 invocations per 30 seconds
5. **PM4 Command Buffer Scanning** - Active and processing
6. **Kernel Functions** - 22 kernel functions implemented (Nt*, Ke*, Ob*, Mm*, Rtl*, Vd*)
7. **Sleep Function** - KeDelayExecutionThread properly implemented
8. **Main Event Loop** - Running at 60 iterations/second
9. **Window Responsiveness** - SDL event loop processing events

### ⚠️ What's Not Working

1. **No Draw Commands** - PM4 scans show draws=0
2. **No File I/O** - Game has not called NtCreateFile/NtOpenFile/NtReadFile
3. **Missing Threads** - Only 3/9 threads created (missing 6 critical threads)
4. **Infinite Sleep Loop** - Game never progresses past initialization
5. **Stale Image** - Window shows garbage/uninitialized backbuffer

## Root Cause Analysis

### Thread Creation Mismatch

**Xenia creates 9 unique game threads:**
1. ✅ `0x828508A8` - Created
2. ✅ `0x82812ED0` - Created
3. ✅ `0x82849D40` - Created
4. ❌ `0x8262E9A8` - **Main thread entry point** (we start this directly, not as thread)
5. ❌ `0x825AA970` - **Critical thread** that triggers VD notify source=1
6. ❌ `0x826E7B90` - Additional thread
7. ❌ `0x826E7BC0` - Additional thread
8. ❌ `0x826E7BF0` - Additional thread
9. ❌ `0x826E7C20` - Additional thread

**Impact**: Thread `0x825AA970` is responsible for triggering `VD notify source=1`, which appears to be a key initialization step that leads to draw commands. Without this thread, the game never progresses.

### Sleep Loop is Normal

**Xenia Log Analysis:**
- Line 1280: Main thread starts sleeping at `lr=0x8262F300`
- Line 1280-317729: Game sleeps **149,148 times**
- Line 317731: First draw command issued

**Our Implementation:**
- Main thread sleeps at `lr=0x8262F300` (SAME ADDRESS!)
- Game sleeps infinitely (never reaches draw commands)

**Conclusion**: The sleep loop is the game's normal way of yielding while waiting for initialization to complete. The issue is not the sleep itself, but that the initialization never completes because critical threads are missing.

### Flag Forcing/Blocking Workaround

The `MW05_UNBLOCK_MAIN` workaround:
- Forces flag at `0x82A2CF40` to 1
- Blocks the game from resetting it to 0
- Interferes with the game's state machine

**Game's intended loop:**
```
1. Wait for flag to become 1
2. Do work
3. Reset flag to 0
4. Loop back to step 1
```

By blocking the reset, we prevent the game from completing its work and progressing through the state machine.

## Xenia vs Our Implementation Timeline

### Xenia (Working)

```
Line 375-380:   Create XMA Decoder and Audio Worker threads (BEFORE game load)
Line 725-944:   Process import table (193 xboxkrnl imports)
Line 1122:      Game starts executing
Line 1227:      Create main thread (entry=0x8262E9A8, suspended=true)
Line 1280:      Main thread starts sleeping at lr=0x8262F300
Line 1280-317729: Sleep 149,148 times (NORMAL!)
Line 35788:     VD notify source=1, NEW THREAD created (0x825AA970)
Line 317731:    First draw command issued!
```

### Our Implementation (Current)

```
Startup:        VBlank pump starts
Startup:        Process import table (388/719 imports)
Startup:        Start main thread directly (entry=0x8262E9A8)
Runtime:        Main thread sleeps at lr=0x8262F300 (SAME AS XENIA!)
Runtime:        Sleep infinitely (never progresses)
Runtime:        Only 3 threads created (missing 6)
Runtime:        No file I/O
Runtime:        No draw commands
```

## Missing Imports Analysis

**Total**: 331/719 imports missing (46%)

**Breakdown by category:**
- **NetDll*** (73) - Networking (not critical for offline play)
- **Xam*** (45) - Xbox Application Model (UI, content, sessions)
- **XMA*** (28) - Audio codec (not critical for rendering)
- **XeCrypt*** (12) - Cryptography (not critical for rendering)
- **Others** (173) - Various kernel and system functions

**Impact**: Some of these missing imports might be blocking thread creation or initialization steps.

## Tools Created

### `tools/analyze_xenia_log.py`

Comprehensive Xenia log analyzer that:
- Finds import table processing
- Tracks thread creation sequence (9 threads identified)
- Analyzes sleep loop patterns (149,148 sleeps found)
- Compares with our trace logs
- Exports initialization sequence to `tools/xenia_init_sequence.txt`

**Usage:**
```bash
python tools/analyze_xenia_log.py
```

**Output:**
- Thread creation timeline
- Sleep loop analysis
- Comparison with our implementation
- Missing threads identified

## Next Steps to Fix

### Priority 1: Understand Why Threads Aren't Created

1. **Investigate thread creation calls** - Check if the game is calling ExCreateThread for the missing threads
2. **Check for missing imports** - Some Xam* or kernel functions might be required for thread creation
3. **Trace execution flow** - Understand what should trigger thread creation

### Priority 2: Remove Workarounds

1. **Remove flag forcing/blocking** - Let the game run naturally
2. **Remove MW05_UNBLOCK_MAIN** - This workaround interferes with the state machine
3. **Let initialization complete naturally** - The sleep loop will end when all steps complete

### Priority 3: Implement Missing Imports

1. **Focus on Xam* functions** - These might be critical for initialization
2. **Implement missing kernel functions** - Some might be required for thread creation
3. **Prioritize based on Xenia log** - Implement functions that Xenia shows being called

### Priority 4: Fix Thread Creation

1. **Create main thread as suspended** - Match Xenia's behavior
2. **Ensure all threads are created** - Investigate why 6 threads are missing
3. **Verify thread entry points** - Ensure all entry points are registered

## Conclusion

The game is stuck in initialization because critical threads are never created. The sleep loop is normal behavior - the game is designed to sleep while waiting for initialization to complete. The workarounds we've implemented (flag forcing/blocking) are actually preventing the game from progressing naturally.

The real fix requires:
1. Understanding why threads aren't being created
2. Implementing missing imports that might be blocking thread creation
3. Removing workarounds that interfere with the game's state machine
4. Letting the initialization complete naturally

This is a complex, multi-faceted issue that requires careful investigation and implementation rather than quick fixes.

## Files Modified

- `AGENTS.md` - Updated with current status and Xenia comparison
- `DEBUG_FINDINGS.md` - Comprehensive debugging findings
- `tools/analyze_xenia_log.py` - Created comprehensive Xenia log analyzer
- `tools/analyze_missing_imports.py` - Analyzes missing imports
- `tools/analyze_sleep_pattern.py` - Analyzes sleep patterns
- `tools/analyze_trace_functions.py` - Analyzes function call frequency
- `Mw05Recomp/kernel/imports.cpp` - Implemented 22 kernel functions
- `Mw05Recomp/main.cpp` - Added diagnostic logging
- `Mw05Recomp/gpu/video.cpp` - Added diagnostic logging
- `Mw05Recomp/cpu/mw05_trace_threads.cpp` - Modified UnblockMainThreadEarly to call sub_82442080
- `run_minimal.ps1` - Set MW05_FORCE_PRESENT=1
- `test_window_response.ps1` - Created window responsiveness tester
- `debug_blocking.ps1` - Created automated debug script

