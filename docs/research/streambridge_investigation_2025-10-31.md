# StreamBridge Investigation - 2025-10-31

## Summary

**ROOT CAUSE IDENTIFIED**: Game is NOT calling the loader/asset dispatcher, which is why no files are being loaded and `draws=0`.

## Test Results

### Test Configuration
- **StreamBridge**: Enabled with relaxed LR checking (`MW05_STREAM_ANY_LR=1`)
- **Fallback boot**: Enabled (`MW05_STREAM_FALLBACK_BOOT=1`)
- **ACK no path**: Enabled (`MW05_STREAM_ACK_NO_PATH=1`)
- **Duration**: 30 seconds

### Results
- ❌ **NO StreamBridge activity** - game is NOT trying to load files
- ❌ **NO sentinel writes (0x0A000000)** - game is NOT calling the loader dispatcher
- ✅ **72 Present calls, 18 VdSwap calls** - graphics system is running
- ✅ **2040 GPU commands** - PM4 system is working
- ❌ **draws=0** - NO draw commands

## How StreamBridge Works

### Trigger Mechanism
StreamBridge is triggered by a **memory watch system** that detects when the game writes the sentinel value `0x0A000000` to a scheduler block slot.

### Call Chain
1. Game calls loader/asset dispatcher (address range `0x8215BE00-0x8215C3FF`)
2. Dispatcher writes sentinel `0x0A000000` to scheduler block slot `[block+0x10]`
3. Memory watch system detects the write (in `kernel/trace.h`)
4. `Mw05HandleSchedulerSentinel()` is called (in `mw05_streaming_bridge.cpp`)
5. StreamBridge attempts to decode file path from scheduler block
6. If successful, performs file I/O and clears the block
7. Game's loader pump advances to next job

### Key Code Locations
- **Handler**: `Mw05Recomp/cpu/mw05_streaming_bridge.cpp::Mw05HandleSchedulerSentinel()`
- **Watch system**: `Mw05Recomp/kernel/trace.h` (Store32BE_W, Store128BE_W)
- **Loader dispatcher range**: `0x8215BE00-0x8215C3FF`
- **Sentinel value**: `0x0A000000`

## Root Cause

**The game is NOT calling the loader/asset dispatcher!**

This means:
1. Game never writes the sentinel value `0x0A000000`
2. StreamBridge is never triggered
3. No files are loaded
4. Game cannot progress to rendering (needs textures, models, etc.)
5. Result: `draws=0`

## Why Game Isn't Calling Loader Dispatcher

The game is stuck in initialization and never progresses to the point where it would:
1. Initialize the loader/asset system
2. Start loading boot files (GLOBALMEMORYFILE.BIN, etc.)
3. Load textures and models
4. Begin rendering

## Evidence from Logs

### No Sentinel Writes
```
[INFO] NO sentinel writes detected
```

### No StreamBridge Activity
```
[FAIL] NO StreamBridge activity - game is not trying to load files!
```

### Graphics System Running
```
[PRESENT] Present calls: 72
[VDSWAP] VdSwap calls: 18
[PM4] PM4 scan operations: 14
```

### No Draw Commands
```
[DRAWS] draws=0
```

### VBlank Callback Issues
```
[QUEUE-DEBUG] ProcessMW05Queue #822: base=40007180 qhead=00000000 qtail=00000000 vblank_cb=00000000
[QUEUE-DEBUG]   VBlank callback NOT SET (a2[3899]=0) - game won't process queue!
```

## Next Steps

### 1. Investigate Initialization Sequence
- What initialization must complete before loader dispatcher is called?
- Is there a missing initialization callback?
- Is the game waiting for some event or condition?

### 2. Check Loader Dispatcher Initialization
- Use IDA Pro API to analyze loader dispatcher at `0x8215BE00-0x8215C3FF`
- Find what calls the loader dispatcher
- Identify initialization requirements

### 3. Compare with Working Xbox 360 Version
- How does the game initialize on real hardware?
- What triggers the loader dispatcher?
- Are there any missing kernel functions or callbacks?

### 4. Check for Missing Initialization
- Display initialization (dimensions are zero, viewport invalid)
- Loader system initialization
- Asset manager initialization
- File system initialization

## Conclusion

The `draws=0` issue is NOT caused by:
- ❌ File I/O hooks (StreamBridge exists and works)
- ❌ Memory allocation (BaseHeap is working correctly)
- ❌ Worker threads (they are running)
- ❌ PM4 system (it's processing commands)

The issue IS caused by:
- ✅ **Game stuck in initialization** - never calls loader dispatcher
- ✅ **No file loading** - loader dispatcher not called
- ✅ **No assets** - cannot render without textures/models
- ✅ **Missing initialization step** - something prevents progression

The game needs to complete some critical initialization step before it will call the loader dispatcher and start loading files. Once files are loaded, the game can progress to rendering and issue draw commands.

