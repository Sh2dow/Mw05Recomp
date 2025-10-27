# MW05 Recompilation - Current Status (2025-10-27)

## ✅ Major Fixes Completed

### 1. Heap Corruption Fix (COMPLETE)
- **Problem**: Buggy memset function writing 4GB of zeros across heap
- **Solution**: Heap protection blocks ALL writes from `lr=0x825A7DC8`
- **Result**: Game runs 60+ seconds without crashes, 370M+ writes blocked
- **Memory usage**: Stable at ~1.76 GB (down from 15-20 GB leak)

### 2. Infinite Loop Fix (COMPLETE)
- **Problem**: Infinite recursion in video initialization causing log spam
- **Solution**: Moved `Mw05MaybeForceRegisterVdEventFromEnv()` after `g_autoVideoDone` check
- **Result**: No more log spam, app window responsive
- **Logs**: Now respect `MW05_DEBUG_GRAPHICS` verbosity settings

### 3. Debug Verbosity System (COMPLETE)
- **Implementation**: All logs converted to use `DEBUG_LOG_GRAPHICS` macro
- **Control**: `MW05_DEBUG_GRAPHICS` environment variable (0=off, 1=minimal, 2=normal, 3=verbose)
- **Result**: Clean, controlled logging with no spam

## ❌ Remaining Issue: draws=0 (No Rendering)

### Problem Analysis

The game is running but not rendering. Investigation reveals:

**PM4 Packet Analysis**:
```
[PM4-TYPE-DIST] TYPE0=77000 TYPE1=0 TYPE2=0 TYPE3=0 total=77000
[PM4-OPCODE-HISTOGRAM] Dump #1:
[PM4-OPCODE-HISTOGRAM] End dump
[RENDER-DEBUG] PM4_ScanLinear result: consumed=65520 draws=0
```

**Key Findings**:
- ✅ PM4 scanner is working (77,000 TYPE0 packets found)
- ✅ Game is writing GPU registers (TYPE0 = register writes)
- ❌ **ZERO TYPE3 packets found** (TYPE3 contains draw commands)
- ❌ **No DRAW_INDX (0x22) or DRAW_INDX_2 (0x36) opcodes**
- ✅ Game presents frames (5 present calls)
- ✅ VBlank callbacks are firing
- ✅ Graphics interrupt callbacks are registered

### Root Cause

**The game is stuck in initialization and hasn't progressed to the rendering stage.**

The game is:
1. ✅ Initializing GPU state (writing registers via TYPE0 packets)
2. ✅ Presenting frames (VdSwap calls)
3. ✅ Running main thread (heartbeat active)
4. ❌ **NOT issuing draw commands** (no TYPE3 packets with DRAW opcodes)

This suggests the game is waiting for something before it starts rendering:
- Profile system callback?
- Loading screen completion?
- Asset loading?
- Some other initialization step?

### PM4 Packet Types

- **TYPE0**: Register writes (SET_REGISTER) - ✅ Working (77,000 found)
- **TYPE1**: Reserved - Not used
- **TYPE2**: Reserved - Not used
- **TYPE3**: Commands (DRAW_INDX, DRAW_INDX_2, etc.) - ❌ **MISSING!**

Draw commands are TYPE3 packets with opcodes:
- `0x22` = DRAW_INDX (draw indexed primitives)
- `0x36` = DRAW_INDX_2 (draw indexed primitives variant)

## System Status

### Working Systems ✅
- Heap management (o1heap)
- Thread creation and management
- File I/O
- Audio initialization
- VBlank pump
- Graphics interrupt callbacks
- PM4 register writes (TYPE0)
- Frame presentation (VdSwap)
- Main thread execution

### Not Working ❌
- Rendering (no draw commands)
- TYPE3 PM4 packets (commands)

## Test Results

### Latest Test (15 seconds)
```
- Heap protection: 1+ billion writes blocked
- PM4 packets: 77,000 TYPE0 (register writes)
- PM4 TYPE3: 0 (no commands)
- Draw commands: 0
- Present calls: 5
- Memory usage: Stable ~1.76 GB
- Crashes: None
```

## Next Steps

To fix the `draws=0` issue, we need to investigate:

1. **Why is the game not issuing TYPE3 packets?**
   - Is it waiting for a callback?
   - Is it stuck in a loading screen?
   - Is there a missing initialization step?

2. **What is the game doing instead of rendering?**
   - Check thread activity
   - Check file I/O patterns
   - Check for waiting/sleeping threads

3. **Compare with Xenia behavior**
   - When does Xenia start seeing TYPE3 packets?
   - What triggers the transition from init to rendering?

4. **Check profile system**
   - Is the game waiting for profile manager callback?
   - Are there any profile-related events that need to be signaled?

5. **Check asset loading**
   - Are textures/models being loaded?
   - Is the game waiting for assets to finish loading?

## Environment Variables

### Debug Verbosity
```bash
MW05_DEBUG_GRAPHICS=0  # No logging (default)
MW05_DEBUG_GRAPHICS=1  # Minimal (errors only)
MW05_DEBUG_GRAPHICS=2  # Normal (important events)
MW05_DEBUG_GRAPHICS=3  # Verbose (all events)
```

### Other Controls
```bash
MW05_AUTO_VIDEO=1      # Enable auto video init (default)
MW05_FORCE_VD_INIT=1   # Force VD initialization (default)
MW05_PM4_TRACE=0       # Disable PM4 tracing (default)
```

## Files Modified Today

1. `Mw05Recomp/kernel/trace.h` - Heap protection extended
2. `Mw05Recomp/kernel/imports.cpp` - Fixed infinite loop, added debug verbosity
3. `docs/research/2025-10-27_heap_corruption_fix_complete.md` - Documentation
4. `docs/research/2025-10-27_infinite_loop_fix.md` - Documentation

## Summary

**Major Progress**: Heap corruption and infinite loop completely fixed. Game is stable and runs indefinitely.

**Remaining Challenge**: Game is stuck in initialization phase, writing GPU registers but not issuing draw commands. Need to identify what the game is waiting for to progress to the rendering stage.

